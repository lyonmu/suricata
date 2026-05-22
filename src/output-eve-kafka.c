/* Copyright (C) 2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Suricata Team
 *
 * File-like output for logging: Apache Kafka
 *
 * This module implements EVE output to Apache Kafka using librdkafka.
 * It uses a per-thread queue for decoupling Suricata's packet processing
 * from Kafka message production, ensuring that Kafka failures do not
 * affect packet processing performance.
 *
 * \note Queue overwrites oldest messages when full.
 * This may cause out-of-order delivery during high load.
 * For strict ordering, increase ring_buffer_size.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <limits.h>

#include "suricata-common.h"
#include "output-eve.h"
#include "output-eve-kafka.h"
#include "conf.h"
#include "util-debug.h"
#include "util-unittest.h"

#ifdef HAVE_LIBRDKAFKA

#include <librdkafka/rdkafka.h>

#if RD_KAFKA_VERSION < 0x020300ff
#error "Kafka EVE output requires librdkafka >= 2.3.0"
#endif

#define OUTPUT_NAME "kafka"
#define KAFKA_QUEUE_FULL_RETRY_MAX 3
#define KAFKA_QUEUE_FULL_RETRY_POLL_MS 10

/* Forward declarations */
static void *KafkaProducerThread(void *arg);
static void KafkaDeliveryReportCallback(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque);
static void KafkaLogCallback(const rd_kafka_t *rk, int level, const char *fac, const char *buf);
static void KafkaFreeConfig(KafkaSetup *setup);
static bool KafkaQueueFullRetryBudget(const uint32_t retry_count);
static inline bool KafkaShouldRetryQueueFull(
        const rd_kafka_resp_err_t ret, const uint32_t retry_count);
typedef rd_kafka_resp_err_t (*KafkaProduceHookFunc)(void *ctx, const char *topic,
        char *data, const size_t len);
typedef void (*KafkaPollHookFunc)(void *ctx, const int timeout_ms);
static rd_kafka_resp_err_t KafkaProduceWithRetryInternal(void *hook_ctx, const char *topic,
        char *data, const size_t len, KafkaProduceHookFunc produce_hook,
        KafkaPollHookFunc poll_hook, uint32_t *retries_out);
typedef int (*KafkaCreateTopicHookFunc)(void *ctx, const char *topic, int32_t partition_count);
static int KafkaMaybeCreateTopic(const KafkaSetup *setup, const char *topic,
        KafkaCreateTopicHookFunc hook, void *hook_ctx);
typedef rd_kafka_resp_err_t (*KafkaDrainProduceHookFunc)(
        void *ctx, const char *topic, int32_t partition,
        const uint8_t *data, size_t len, const void *key, size_t key_len);
typedef int (*KafkaDrainPollHookFunc)(void *ctx, void *rk, int timeout_ms);
static rd_kafka_resp_err_t KafkaDrainProduceHook(void *ctx, const char *topic,
        int32_t partition, const uint8_t *data, size_t len, const void *key, size_t key_len);
static int KafkaDrainPollHook(void *ctx, void *rk, int timeout_ms);
static uint32_t KafkaDrainQueuesInternal(SCEveKafkaQueueRegistry *registry,
        uint32_t max_batch, int idle_poll_ms, KafkaDrainProduceHookFunc produce_hook,
        void *produce_ctx, KafkaDrainPollHookFunc poll_hook, void *poll_ctx);
static SCEveKafkaQueueEntry *KafkaQueuePop(SCEveKafkaQueue *queue);

static int KafkaDupString(const char *src, char **dst, const char *name)
{
    *dst = SCStrdup(src);
    if (*dst == NULL) {
        SCLogError("Kafka: failed to allocate memory for %s", name);
        return -1;
    }
    return 0;
}

static int KafkaValidateIntRange(
        const char *name, const intmax_t value, const intmax_t min, const intmax_t max)
{
    if (value < min || value > max) {
        SCLogError("Kafka: invalid value for %s: %" PRIdMAX
                   " (must be between %" PRIdMAX " and %" PRIdMAX ")",
                name, value, min, max);
        return -1;
    }
    return 0;
}

static int KafkaValidateIntTarget(const char *name, const intmax_t value, const intmax_t min)
{
    return KafkaValidateIntRange(name, value, min, INT_MAX);
}

static bool KafkaQueueFullRetryBudget(const uint32_t retry_count)
{
    return retry_count < KAFKA_QUEUE_FULL_RETRY_MAX;
}

static inline bool KafkaShouldRetryQueueFull(
        const rd_kafka_resp_err_t ret, const uint32_t retry_count)
{
    return ret == RD_KAFKA_RESP_ERR__QUEUE_FULL && KafkaQueueFullRetryBudget(retry_count);
}

static rd_kafka_resp_err_t KafkaDrainProduceHook(void *ctx, const char *topic,
        int32_t partition, const uint8_t *data, size_t len, const void *key, size_t key_len)
{
    SCEveKafkaContext *kctx = (SCEveKafkaContext *)ctx;
    (void)partition;
    (void)key;
    (void)key_len;

    /* Use COPY so drain helper retains ownership and can free after hook returns.
     * Retries for QUEUE_FULL are handled inline. */
    uint32_t retries = 0;
    while (1) {
        rd_kafka_resp_err_t ret = rd_kafka_producev(kctx->rk,
                RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_VALUE((void *)data, len),
                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY), RD_KAFKA_V_END);
        if (ret == RD_KAFKA_RESP_ERR_NO_ERROR) {
            return ret;
        }
        if (KafkaShouldRetryQueueFull(ret, retries)) {
            retries++;
            rd_kafka_poll(kctx->rk, KAFKA_QUEUE_FULL_RETRY_POLL_MS);
            continue;
        }
        /* Queue full beyond budget or other error — message will be dropped
         * by the drain helper (which frees entry->data). */
        SC_ATOMIC_ADD(kctx->messages_dropped_produce, 1);
        return ret;
    }
}

static int KafkaDrainPollHook(void *ctx, void *rk, int timeout_ms)
{
    SCEveKafkaContext *kctx = (SCEveKafkaContext *)ctx;
    (void)rk;
    return rd_kafka_poll(kctx->rk, timeout_ms);
}

static uint32_t KafkaDrainQueuesInternal(SCEveKafkaQueueRegistry *registry,
        uint32_t max_batch, int idle_poll_ms, KafkaDrainProduceHookFunc produce_hook,
        void *produce_ctx, KafkaDrainPollHookFunc poll_hook, void *poll_ctx)
{
    uint32_t total_drained = 0;
    bool did_work = false;

    SCMutexLock(&registry->lock);
    uint32_t queue_count = registry->queue_count;
    SCMutexUnlock(&registry->lock);

    if (queue_count == 0) {
        poll_hook(poll_ctx, NULL, idle_poll_ms);
        return 0;
    }

    for (uint32_t i = 0; i < queue_count; i++) {
        SCMutexLock(&registry->lock);
        uint32_t idx = registry->next_queue;
        registry->next_queue = (idx + 1) % queue_count;
        SCMutexUnlock(&registry->lock);

        SCEveKafkaQueue *queue;
        SCMutexLock(&registry->lock);
        queue = registry->queues[idx];
        SCMutexUnlock(&registry->lock);

        for (uint32_t j = 0; j < max_batch; j++) {
            SCEveKafkaQueueEntry *entry = KafkaQueuePop(queue);
            if (entry == NULL) {
                break;
            }
            rd_kafka_resp_err_t err = produce_hook(produce_ctx, "eve",
                    RD_KAFKA_PARTITION_UA, entry->data, entry->len, NULL, 0);
            if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
                /* produce failed, entry data lost — counted by produce hook */
            }
            SCFree(entry->data);
            SCFree(entry);
            total_drained++;
            did_work = true;
        }
    }

    poll_hook(poll_ctx, NULL, did_work ? 0 : idle_poll_ms);
    return total_drained;
}

static rd_kafka_resp_err_t KafkaProduceWithRetryInternal(void *hook_ctx, const char *topic,
        char *data, const size_t len, KafkaProduceHookFunc produce_hook,
        KafkaPollHookFunc poll_hook, uint32_t *retries_out)
{
    uint32_t retries = 0;

    while (1) {
        rd_kafka_resp_err_t ret = produce_hook(hook_ctx, topic, data, len);
        if (ret == RD_KAFKA_RESP_ERR_NO_ERROR) {
            if (retries_out != NULL) {
                *retries_out = retries;
            }
            return ret;
        }

        if (KafkaShouldRetryQueueFull(ret, retries)) {
            retries++;
            poll_hook(hook_ctx, KAFKA_QUEUE_FULL_RETRY_POLL_MS);
            continue;
        }

        if (retries_out != NULL) {
            *retries_out = retries;
        }
        return ret;
    }
}

static void KafkaQueueDropOldestLocked(SCEveKafkaQueue *queue)
{
    SCEveKafkaQueueEntry *entry = &queue->entries[queue->head];
    queue->current_bytes -= entry->len;
    SCFree(entry->data);
    entry->data = NULL;
    entry->len = 0;
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    queue->dropped++;
}

static SCEveKafkaQueue *KafkaQueueCreate(const uint32_t capacity, const uint64_t max_bytes)
{
    if (capacity < 2 || max_bytes == 0) {
        return NULL;
    }
    SCEveKafkaQueue *queue = SCCalloc(1, sizeof(*queue));
    if (queue == NULL) {
        return NULL;
    }
    queue->entries = SCCalloc(capacity, sizeof(*queue->entries));
    if (queue->entries == NULL) {
        SCFree(queue);
        return NULL;
    }
    queue->capacity = capacity;
    queue->max_bytes = max_bytes;
    SCSpinInit(&queue->lock, 0);
    return queue;
}

static KafkaQueuePushResult KafkaQueuePush(
        SCEveKafkaQueue *queue, const uint8_t *data, const size_t len)
{
    KafkaQueuePushResult result;
    SCSpinLock(&queue->lock);
    if (queue->closing) {
        result = KAFKA_QUEUE_PUSH_CLOSED;
        goto unlock;
    }
    if (len > queue->max_bytes) {
        queue->dropped++;
        result = KAFKA_QUEUE_PUSH_DROPPED;
        goto unlock;
    }
    while (queue->count >= queue->capacity) {
        KafkaQueueDropOldestLocked(queue);
    }
    while (queue->current_bytes + len > queue->max_bytes && queue->count > 0) {
        KafkaQueueDropOldestLocked(queue);
    }
    uint8_t *copy = SCMalloc(len);
    if (copy == NULL) {
        queue->dropped++;
        result = KAFKA_QUEUE_PUSH_DROPPED;
        goto unlock;
    }
    memcpy(copy, data, len);
    queue->entries[queue->tail].data = copy;
    queue->entries[queue->tail].len = len;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;
    queue->current_bytes += len;
    queue->pushed++;
    result = KAFKA_QUEUE_PUSH_OK;
unlock:
    SCSpinUnlock(&queue->lock);
    return result;
}

static SCEveKafkaQueueEntry *KafkaQueuePop(SCEveKafkaQueue *queue)
{
    SCEveKafkaQueueEntry *entry = NULL;
    SCSpinLock(&queue->lock);
    if (queue->count == 0) {
        goto unlock;
    }
    /* Advance head and remove slot from queue BEFORE allocating wrapper.
     * If SCCalloc fails below, the entry data is lost but the queue
     * doesn't get stuck retrying the same entry forever. */
    uint8_t *data = queue->entries[queue->head].data;
    size_t len = queue->entries[queue->head].len;
    queue->entries[queue->head].data = NULL;
    queue->entries[queue->head].len = 0;
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    queue->current_bytes -= len;
    queue->popped++;
    entry = SCCalloc(1, sizeof(*entry));
    if (entry == NULL) {
        SCFree(data);
        goto unlock;
    }
    entry->data = data;
    entry->len = len;
unlock:
    SCSpinUnlock(&queue->lock);
    return entry;
}

static void KafkaQueueClose(SCEveKafkaQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    SCSpinLock(&queue->lock);
    queue->closing = true;
    SCSpinUnlock(&queue->lock);
}

static void KafkaQueueDestroy(SCEveKafkaQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    for (uint32_t i = 0; i < queue->capacity; i++) {
        SCFree(queue->entries[i].data);
    }
    SCFree(queue->entries);
    SCSpinDestroy(&queue->lock);
    SCFree(queue);
}

static SCEveKafkaQueueRegistry *KafkaQueueRegistryCreate(void)
{
    SCEveKafkaQueueRegistry *registry = SCCalloc(1, sizeof(*registry));
    if (registry == NULL) {
        return NULL;
    }
    registry->queue_capacity = 4;
    registry->queues = SCCalloc(registry->queue_capacity, sizeof(*registry->queues));
    if (registry->queues == NULL) {
        SCFree(registry);
        return NULL;
    }
    SCMutexInit(&registry->lock, NULL);
    return registry;
}

static int KafkaQueueRegistryRegister(SCEveKafkaQueueRegistry *registry, SCEveKafkaQueue *queue)
{
    DEBUG_VALIDATE_BUG_ON(registry == NULL);
    DEBUG_VALIDATE_BUG_ON(queue == NULL);

    SCMutexLock(&registry->lock);
    if (registry->queue_count == registry->queue_capacity) {
        uint32_t new_capacity = registry->queue_capacity * 2;
        SCEveKafkaQueue **new_queues =
                SCRealloc(registry->queues, new_capacity * sizeof(*registry->queues));
        if (new_queues == NULL) {
            SCMutexUnlock(&registry->lock);
            return -1;
        }
        registry->queues = new_queues;
        registry->queue_capacity = new_capacity;
    }
    registry->queues[registry->queue_count++] = queue;
    SCMutexUnlock(&registry->lock);
    return 0;
}

static void KafkaQueueRegistryCloseAll(SCEveKafkaQueueRegistry *registry)
{
    if (registry == NULL) {
        return;
    }
    SCMutexLock(&registry->lock);
    for (uint32_t i = 0; i < registry->queue_count; i++) {
        KafkaQueueClose(registry->queues[i]);
    }
    SCMutexUnlock(&registry->lock);
}

static void KafkaQueueRegistryDestroy(SCEveKafkaQueueRegistry *registry)
{
    if (registry == NULL) {
        return;
    }
    for (uint32_t i = 0; i < registry->queue_count; i++) {
        KafkaQueueDestroy(registry->queues[i]);
    }
    SCFree(registry->queues);
    SCMutexDestroy(&registry->lock);
    SCFree(registry);
}

/**
 * \brief Parse Kafka configuration
 */
static int KafkaParseConfig(const SCConfNode *conf, KafkaSetup *setup)
{
    const char *val;

    /* Required settings */
    val = SCConfNodeLookupChildValue(conf, "brokers");
    if (val == NULL) {
        SCLogError("Kafka: 'brokers' configuration required");
        return -1;
    }
    if (KafkaDupString(val, &setup->brokers, "brokers") != 0) {
        goto error;
    }

    val = SCConfNodeLookupChildValue(conf, "topic");
    if (val == NULL) {
        SCLogError("Kafka: 'topic' configuration required");
        goto error;
    }
    if (KafkaDupString(val, &setup->topic, "topic") != 0) {
        goto error;
    }

    /* Optional settings with defaults */
    val = SCConfNodeLookupChildValue(conf, "client-id");
    if (KafkaDupString(val ? val : "suricata", &setup->client_id, "client-id") != 0) {
        goto error;
    }

    /* Compression */
    val = SCConfNodeLookupChildValue(conf, "compression");
    if (val == NULL || strcmp(val, "none") == 0) {
        setup->compression = KAFKA_COMPRESSION_NONE;
    } else if (strcmp(val, "gzip") == 0) {
        setup->compression = KAFKA_COMPRESSION_GZIP;
    } else if (strcmp(val, "snappy") == 0) {
        setup->compression = KAFKA_COMPRESSION_SNAPPY;
    } else if (strcmp(val, "lz4") == 0) {
        setup->compression = KAFKA_COMPRESSION_LZ4;
    } else if (strcmp(val, "zstd") == 0) {
        setup->compression = KAFKA_COMPRESSION_ZSTD;
    } else {
        SCLogWarning("Kafka: unknown compression '%s', using none", val);
        setup->compression = KAFKA_COMPRESSION_NONE;
    }

    /* Acks */
    val = SCConfNodeLookupChildValue(conf, "acks");
    if (val == NULL || strcmp(val, "1") == 0) {
        setup->acks = KAFKA_ACKS_ONE;
    } else if (strcmp(val, "0") == 0) {
        setup->acks = KAFKA_ACKS_ZERO;
    } else if (strcasecmp(val, "all") == 0 || strcmp(val, "-1") == 0) {
        setup->acks = KAFKA_ACKS_ALL;
    } else {
        SCLogWarning("Kafka: unknown acks '%s', using 1", val);
        setup->acks = KAFKA_ACKS_ONE;
    }

    /* Numeric settings with defaults */
    setup->partition = RD_KAFKA_PARTITION_UA;
    setup->topic_auto_create = false;
    setup->topic_partitions = KAFKA_TOPIC_PARTITIONS_DEFAULT;
    setup->ring_buffer_size = KAFKA_RING_BUFFER_SIZE_DEFAULT;
    setup->ring_buffer_max_bytes = KAFKA_RING_BUFFER_MAX_BYTES;
    setup->max_drain_batch = KAFKA_MAX_DRAIN_BATCH_DEFAULT;
    setup->idle_poll_ms = KAFKA_IDLE_POLL_MS_DEFAULT;

    /* librdkafka internal queue settings with defaults */
    setup->queue_buffering_max_messages = KAFKA_QUEUE_BUFFERING_MAX_MSGS;
    setup->queue_buffering_max_kbytes = KAFKA_QUEUE_BUFFERING_MAX_KBYTES;
    setup->message_timeout_ms = KAFKA_MESSAGE_TIMEOUT_MS;
    setup->socket_timeout_ms = KAFKA_SOCKET_TIMEOUT_MS;
    setup->metadata_max_age_ms = KAFKA_METADATA_MAX_AGE_MS;
    setup->retry_backoff_ms = KAFKA_RETRY_BACKOFF_MS;
    setup->retry_backoff_max_ms = KAFKA_RETRY_BACKOFF_MAX_MS;
    setup->reconnect_backoff_ms = KAFKA_RECONNECT_BACKOFF_MS;
    setup->reconnect_backoff_max_ms = KAFKA_RECONNECT_BACKOFF_MAX_MS;
    setup->linger_ms = KAFKA_LINGER_MS;

    /* Security defaults */
    setup->security_protocol = KAFKA_SECURITY_PLAINTEXT;
    setup->ssl_ca_location = NULL;
    setup->ssl_certificate_location = NULL;
    setup->ssl_key_location = NULL;
    setup->ssl_key_password = NULL;
    setup->sasl_mechanism = NULL;
    setup->sasl_username = NULL;
    setup->sasl_password = NULL;

    /* Parse optional overrides */
    intmax_t intval;
    int boolval = 0;
    if (SCConfGetChildValueBool(conf, "topic-auto-create", &boolval) == 1) {
        setup->topic_auto_create = boolval != 0;
    }
    if (SCConfGetChildValueInt(conf, "partition", &intval)) {
        if (KafkaValidateIntTarget("partition", intval, RD_KAFKA_PARTITION_UA) != 0) {
            goto error;
        }
        setup->partition = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "topic-partitions", &intval)) {
        if (KafkaValidateIntTarget("topic-partitions", intval, 1) != 0) {
            goto error;
        }
        setup->topic_partitions = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "ring-buffer-size", &intval)) {
        if (KafkaValidateIntTarget("ring-buffer-size", intval, 2) != 0) {
            goto error;
        }
        setup->ring_buffer_size = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "ring-buffer-max-bytes", &intval)) {
        if (KafkaValidateIntTarget("ring-buffer-max-bytes", intval, 1) != 0) {
            goto error;
        }
        setup->ring_buffer_max_bytes = (uint64_t)intval;
    }
    if (SCConfGetChildValueInt(conf, "max-drain-batch", &intval)) {
        if (KafkaValidateIntTarget("max-drain-batch", intval, 1) != 0) {
            goto error;
        }
        setup->max_drain_batch = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "idle-poll-ms", &intval)) {
        if (KafkaValidateIntTarget("idle-poll-ms", intval, 1) != 0) {
            goto error;
        }
        setup->idle_poll_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "queue-buffering-max-messages", &intval)) {
        if (KafkaValidateIntTarget("queue-buffering-max-messages", intval, 1) != 0) {
            goto error;
        }
        setup->queue_buffering_max_messages = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "queue-buffering-max-kbytes", &intval)) {
        if (KafkaValidateIntTarget("queue-buffering-max-kbytes", intval, 1) != 0) {
            goto error;
        }
        setup->queue_buffering_max_kbytes = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "message-timeout-ms", &intval)) {
        if (KafkaValidateIntTarget("message-timeout-ms", intval, 1) != 0) {
            goto error;
        }
        setup->message_timeout_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "socket-timeout-ms", &intval)) {
        if (KafkaValidateIntTarget("socket-timeout-ms", intval, 1) != 0) {
            goto error;
        }
        setup->socket_timeout_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "metadata-max-age-ms", &intval)) {
        if (KafkaValidateIntTarget("metadata-max-age-ms", intval, 1) != 0) {
            goto error;
        }
        setup->metadata_max_age_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "retry-backoff-ms", &intval)) {
        if (KafkaValidateIntTarget("retry-backoff-ms", intval, 0) != 0) {
            goto error;
        }
        setup->retry_backoff_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "retry-backoff-max-ms", &intval)) {
        if (KafkaValidateIntTarget("retry-backoff-max-ms", intval, 0) != 0) {
            goto error;
        }
        setup->retry_backoff_max_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "reconnect-backoff-ms", &intval)) {
        if (KafkaValidateIntTarget("reconnect-backoff-ms", intval, 1) != 0) {
            goto error;
        }
        setup->reconnect_backoff_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "reconnect-backoff-max-ms", &intval)) {
        if (KafkaValidateIntTarget("reconnect-backoff-max-ms", intval, 1) != 0) {
            goto error;
        }
        setup->reconnect_backoff_max_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "linger-ms", &intval)) {
        if (KafkaValidateIntTarget("linger-ms", intval, 0) != 0) {
            goto error;
        }
        setup->linger_ms = (int)intval;
    }

    if (setup->reconnect_backoff_max_ms < setup->reconnect_backoff_ms) {
        SCLogError("Kafka: invalid reconnect backoff configuration: reconnect-backoff-max-ms "
                   "(%d) must be >= reconnect-backoff-ms (%d)",
                setup->reconnect_backoff_max_ms, setup->reconnect_backoff_ms);
        goto error;
    }
    if (setup->retry_backoff_max_ms < setup->retry_backoff_ms) {
        SCLogError("Kafka: invalid retry backoff configuration: retry-backoff-max-ms (%d) "
                   "must be >= retry-backoff-ms (%d)",
                setup->retry_backoff_max_ms, setup->retry_backoff_ms);
        goto error;
    }

    /* Security settings */
    val = SCConfNodeLookupChildValue(conf, "security-protocol");
    if (val != NULL) {
        if (strcmp(val, "plaintext") == 0) {
            setup->security_protocol = KAFKA_SECURITY_PLAINTEXT;
        } else if (strcmp(val, "ssl") == 0) {
            setup->security_protocol = KAFKA_SECURITY_SSL;
        } else if (strcmp(val, "sasl_plaintext") == 0) {
            setup->security_protocol = KAFKA_SECURITY_SASL_PLAINTEXT;
        } else if (strcmp(val, "sasl_ssl") == 0) {
            setup->security_protocol = KAFKA_SECURITY_SASL_SSL;
        } else {
            SCLogWarning("Kafka: unknown security-protocol '%s', using plaintext", val);
        }
    }

    /* SSL settings */
    val = SCConfNodeLookupChildValue(conf, "ssl-ca-location");
    if (val != NULL && KafkaDupString(val, &setup->ssl_ca_location, "ssl-ca-location") != 0) {
        goto error;
    }

    val = SCConfNodeLookupChildValue(conf, "ssl-certificate-location");
    if (val != NULL &&
            KafkaDupString(val, &setup->ssl_certificate_location, "ssl-certificate-location") !=
                    0) {
        goto error;
    }

    val = SCConfNodeLookupChildValue(conf, "ssl-key-location");
    if (val != NULL && KafkaDupString(val, &setup->ssl_key_location, "ssl-key-location") != 0) {
        goto error;
    }

    val = SCConfNodeLookupChildValue(conf, "ssl-key-password");
    if (val != NULL && KafkaDupString(val, &setup->ssl_key_password, "ssl-key-password") != 0) {
        goto error;
    }

    /* SASL settings */
    val = SCConfNodeLookupChildValue(conf, "sasl-mechanism");
    if (val != NULL && KafkaDupString(val, &setup->sasl_mechanism, "sasl-mechanism") != 0) {
        goto error;
    }

    val = SCConfNodeLookupChildValue(conf, "sasl-username");
    if (val != NULL && KafkaDupString(val, &setup->sasl_username, "sasl-username") != 0) {
        goto error;
    }

    val = SCConfNodeLookupChildValue(conf, "sasl-password");
    if (val != NULL && KafkaDupString(val, &setup->sasl_password, "sasl-password") != 0) {
        goto error;
    }

    return 0;

error:
    KafkaFreeConfig(setup);
    memset(setup, 0, sizeof(*setup));
    return -1;
}

/**
 * \brief Free KafkaSetup configuration
 */
static void KafkaFreeConfig(KafkaSetup *setup)
{
    if (setup->brokers) SCFree(setup->brokers);
    if (setup->topic) SCFree(setup->topic);
    if (setup->client_id) SCFree(setup->client_id);
    if (setup->ssl_ca_location) SCFree(setup->ssl_ca_location);
    if (setup->ssl_certificate_location) SCFree(setup->ssl_certificate_location);
    if (setup->ssl_key_location) SCFree(setup->ssl_key_location);
    if (setup->ssl_key_password) SCFree(setup->ssl_key_password);
    if (setup->sasl_mechanism) SCFree(setup->sasl_mechanism);
    if (setup->sasl_username) SCFree(setup->sasl_username);
    if (setup->sasl_password) SCFree(setup->sasl_password);
}

/**
 * \brief Create librdkafka configuration
 */
static rd_kafka_conf_t *KafkaCreateRdKafkaConf(KafkaSetup *setup)
{
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    char errbuf[512];
    char buf[64];

    /* Basic configuration */
    if (rd_kafka_conf_set(conf, "bootstrap.servers", setup->brokers, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set bootstrap.servers: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }
    if (rd_kafka_conf_set(conf, "client.id", setup->client_id, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set client.id: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    /* Message delivery settings - acks */
    const char *acks_str = setup->acks == KAFKA_ACKS_ZERO ? "0" :
                           setup->acks == KAFKA_ACKS_ONE ? "1" : "all";
    if (rd_kafka_conf_set(conf, "request.required.acks", acks_str, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set request.required.acks: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    /* Compression codec */
    const char *compression_str = setup->compression == KAFKA_COMPRESSION_NONE ? "none" :
                                  setup->compression == KAFKA_COMPRESSION_GZIP ? "gzip" :
                                  setup->compression == KAFKA_COMPRESSION_SNAPPY ? "snappy" :
                                  setup->compression == KAFKA_COMPRESSION_LZ4 ? "lz4" : "zstd";
    if (rd_kafka_conf_set(conf, "compression.codec", compression_str, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set compression.codec: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    /* Batch and buffering settings */
    snprintf(buf, sizeof(buf), "%d", setup->linger_ms);
    if (rd_kafka_conf_set(conf, "linger.ms", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set linger.ms: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    snprintf(buf, sizeof(buf), "%d", setup->queue_buffering_max_messages);
    if (rd_kafka_conf_set(conf, "queue.buffering.max.messages", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set queue.buffering.max.messages: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    snprintf(buf, sizeof(buf), "%d", setup->queue_buffering_max_kbytes);
    if (rd_kafka_conf_set(conf, "queue.buffering.max.kbytes", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set queue.buffering.max.kbytes: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    /* Retry and timeout settings */
    snprintf(buf, sizeof(buf), "%d", setup->retry_backoff_ms);
    if (rd_kafka_conf_set(conf, "retry.backoff.ms", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set retry.backoff.ms: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }
    snprintf(buf, sizeof(buf), "%d", setup->retry_backoff_max_ms);
    if (rd_kafka_conf_set(conf, "retry.backoff.max.ms", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set retry.backoff.max.ms: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }
    snprintf(buf, sizeof(buf), "%d", setup->reconnect_backoff_ms);
    if (rd_kafka_conf_set(conf, "reconnect.backoff.ms", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set reconnect.backoff.ms: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }
    snprintf(buf, sizeof(buf), "%d", setup->reconnect_backoff_max_ms);
    if (rd_kafka_conf_set(conf, "reconnect.backoff.max.ms", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set reconnect.backoff.max.ms: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    snprintf(buf, sizeof(buf), "%d", setup->message_timeout_ms);
    if (rd_kafka_conf_set(conf, "message.timeout.ms", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set message.timeout.ms: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    snprintf(buf, sizeof(buf), "%d", setup->socket_timeout_ms);
    if (rd_kafka_conf_set(conf, "socket.timeout.ms", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set socket.timeout.ms: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    snprintf(buf, sizeof(buf), "%d", setup->metadata_max_age_ms);
    if (rd_kafka_conf_set(conf, "metadata.max.age.ms", buf, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set metadata.max.age.ms: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    /* Enable socket keepalive */
    if (rd_kafka_conf_set(conf, "socket.keepalive.enable", "true", errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
        SCLogError("Kafka: Failed to set socket.keepalive.enable: %s", errbuf);
        rd_kafka_conf_destroy(conf);
        return NULL;
    }

    /* Security settings */
    switch (setup->security_protocol) {
        case KAFKA_SECURITY_SSL:
            if (rd_kafka_conf_set(conf, "security.protocol", "SSL", errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                SCLogError("Kafka: Failed to set security.protocol: %s", errbuf);
                rd_kafka_conf_destroy(conf);
                return NULL;
            }
            if (setup->ssl_ca_location) {
                if (rd_kafka_conf_set(conf, "ssl.ca.location", setup->ssl_ca_location, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set ssl.ca.location: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            if (setup->ssl_certificate_location) {
                if (rd_kafka_conf_set(conf, "ssl.certificate.location", setup->ssl_certificate_location, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set ssl.certificate.location: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            if (setup->ssl_key_location) {
                if (rd_kafka_conf_set(conf, "ssl.key.location", setup->ssl_key_location, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set ssl.key.location: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            if (setup->ssl_key_password) {
                if (rd_kafka_conf_set(conf, "ssl.key.password", setup->ssl_key_password, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set ssl.key.password: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            break;
        case KAFKA_SECURITY_SASL_PLAINTEXT:
            if (rd_kafka_conf_set(conf, "security.protocol", "SASL_PLAINTEXT", errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                SCLogError("Kafka: Failed to set security.protocol: %s", errbuf);
                rd_kafka_conf_destroy(conf);
                return NULL;
            }
            if (setup->sasl_mechanism) {
                if (rd_kafka_conf_set(conf, "sasl.mechanism", setup->sasl_mechanism, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set sasl.mechanism: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            if (setup->sasl_username && setup->sasl_password) {
                if (rd_kafka_conf_set(conf, "sasl.username", setup->sasl_username, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set sasl.username: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
                if (rd_kafka_conf_set(conf, "sasl.password", setup->sasl_password, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set sasl.password: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            break;
        case KAFKA_SECURITY_SASL_SSL:
            if (rd_kafka_conf_set(conf, "security.protocol", "SASL_SSL", errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                SCLogError("Kafka: Failed to set security.protocol: %s", errbuf);
                rd_kafka_conf_destroy(conf);
                return NULL;
            }
            if (setup->sasl_mechanism) {
                if (rd_kafka_conf_set(conf, "sasl.mechanism", setup->sasl_mechanism, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set sasl.mechanism: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            if (setup->sasl_username && setup->sasl_password) {
                if (rd_kafka_conf_set(conf, "sasl.username", setup->sasl_username, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set sasl.username: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
                if (rd_kafka_conf_set(conf, "sasl.password", setup->sasl_password, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set sasl.password: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            if (setup->ssl_ca_location) {
                if (rd_kafka_conf_set(conf, "ssl.ca.location", setup->ssl_ca_location, errbuf, sizeof(errbuf)) != RD_KAFKA_CONF_OK) {
                    SCLogError("Kafka: Failed to set ssl.ca.location: %s", errbuf);
                    rd_kafka_conf_destroy(conf);
                    return NULL;
                }
            }
            break;
        default:
            break;
    }

    /* Register callbacks */
    rd_kafka_conf_set_dr_msg_cb(conf, KafkaDeliveryReportCallback);
    rd_kafka_conf_set_log_cb(conf, KafkaLogCallback);

    return conf;
}

/**
 * \brief Delivery report callback
 */
static void KafkaDeliveryReportCallback(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)opaque;
    if (ctx == NULL) return;

    SC_ATOMIC_ADD(ctx->delivery_callback_count, 1);

    if (rkmessage->err) {
        SCLogError("Kafka message delivery failed: %s", rd_kafka_err2str(rkmessage->err));
        SC_ATOMIC_ADD(ctx->messages_failed, 1);
    } else {
        SC_ATOMIC_ADD(ctx->messages_sent, 1);
        SC_ATOMIC_ADD(ctx->bytes_sent, rkmessage->len);
    }
}

/**
 * \brief Log callback - forwards librdkafka logs to Suricata
 */
static void KafkaLogCallback(const rd_kafka_t *rk, int level, const char *fac, const char *buf)
{
    switch (level) {
        case LOG_EMERG:
        case LOG_ALERT:
        case LOG_CRIT:
        case LOG_ERR:
            SCLogError("KAFKA: %s: %s", fac, buf);
            break;
        case LOG_WARNING:
            SCLogWarning("KAFKA: %s: %s", fac, buf);
            break;
        case LOG_NOTICE:
        case LOG_INFO:
            SCLogNotice("KAFKA: %s: %s", fac, buf);
            break;
        case LOG_DEBUG:
            SCLogDebug("KAFKA: %s: %s", fac, buf);
            break;
        default:
            SCLogInfo("KAFKA: %s: %s", fac, buf);
            break;
    }
}

/**
 * \brief Create topic with specified partition count
 *
 * Uses the 'partition' config value to create topic with that many partitions.
 * If partition is -1 (auto) or 0, creates topic with 1 partition.
 * Other topic settings use Kafka broker defaults.
 */
static int KafkaCreateTopic(rd_kafka_t *rk, const char *topic_name, int partition_count, int timeout_ms)
{
    rd_kafka_NewTopic_t *new_topic;
    rd_kafka_queue_t *queue;
    rd_kafka_event_t *event;
    const rd_kafka_CreateTopics_result_t *create_result;
    const rd_kafka_topic_result_t **topic_results;
    size_t topic_resultcnt;
    char errstr[512];
    int ret = 0;

    /* If partition is -1 (auto) or <= 0, use 1 partition */
    if (partition_count <= 0) {
        partition_count = 1;
    }

    SCLogInfo("Kafka: Creating topic '%s' with %d partitions (using broker defaults for other settings)",
              topic_name, partition_count);

    /* Create topic specification */
    /* Use -1 for replication_factor to let broker use default. */
    new_topic = rd_kafka_NewTopic_new(topic_name, partition_count, -1,
                                      errstr, sizeof(errstr));
    if (new_topic == NULL) {
        SCLogError("Kafka: Failed to create NewTopic object: %s", errstr);
        return -1;
    }

    /* Create a temporary queue for the result */
    queue = rd_kafka_queue_new(rk);
    if (queue == NULL) {
        SCLogError("Kafka: Failed to create result queue");
        rd_kafka_NewTopic_destroy(new_topic);
        return -1;
    }

    /* Create topic on broker (asynchronous) */
    rd_kafka_CreateTopics(rk, &new_topic, 1, NULL, queue);

    /* Destroy the new_topic object after passing to CreateTopics */
    rd_kafka_NewTopic_destroy(new_topic);

    /* Wait for result */
    event = rd_kafka_queue_poll(queue, timeout_ms);
    if (event == NULL) {
        SCLogError("Kafka: Timeout waiting for topic creation result");
        rd_kafka_queue_destroy(queue);
        return -1;
    }

    /* Get create topics result */
    create_result = rd_kafka_event_CreateTopics_result(event);
    if (create_result == NULL) {
        SCLogError("Kafka: Failed to get CreateTopics result");
        rd_kafka_event_destroy(event);
        rd_kafka_queue_destroy(queue);
        return -1;
    }

    /* Get topic results */
    topic_results = rd_kafka_CreateTopics_result_topics(create_result, &topic_resultcnt);

    if (topic_resultcnt > 0) {
        rd_kafka_resp_err_t err = rd_kafka_topic_result_error(topic_results[0]);
        if (err == RD_KAFKA_RESP_ERR_NO_ERROR || err == RD_KAFKA_RESP_ERR_TOPIC_ALREADY_EXISTS) {
            if (err == RD_KAFKA_RESP_ERR_TOPIC_ALREADY_EXISTS) {
                SCLogNotice("Kafka: Topic '%s' already exists", topic_name);
            } else {
                SCLogNotice("Kafka: Topic '%s' created successfully with %d partitions",
                          topic_name, partition_count);
            }
            ret = 0;
        } else {
            SCLogError("Kafka: Failed to create topic '%s': %s",
                      topic_name, rd_kafka_topic_result_error_string(topic_results[0]));
            ret = -1;
        }
    } else {
        SCLogError("Kafka: No result from CreateTopics");
        ret = -1;
    }

    /* Cleanup */
    rd_kafka_event_destroy(event);
    rd_kafka_queue_destroy(queue);

    return ret;
}

static int KafkaCreateTopicHook(void *ctx, const char *topic, int32_t partition_count)
{
    SCEveKafkaContext *kctx = (SCEveKafkaContext *)ctx;
    return KafkaCreateTopic(kctx->rk, topic, partition_count, 10000);
}

static int KafkaMaybeCreateTopic(const KafkaSetup *setup, const char *topic,
        KafkaCreateTopicHookFunc hook, void *hook_ctx)
{
    if (!setup->topic_auto_create) {
        SCLogNotice("Kafka: topic auto-create disabled, skipping topic creation for %s", topic);
        return 0;
    }
    SCLogNotice("Kafka: creating topic %s with %d partitions", topic, setup->topic_partitions);
    return hook(hook_ctx, topic, setup->topic_partitions);
}

/**
 * \brief Background producer thread
 *
 * Thread lifecycle:
 * 1. Named "SCKafkaProd" via SCSetThreadName() for debugging
 * 2. Loops until stop_flag is set or Suricata shutdown signal
 * 3. Round-robins across registered per-thread queues via KafkaDrainQueuesInternal
 * 4. Calls rd_kafka_poll() regularly to trigger delivery callbacks
 * 5. On exit: closes all queues, drains remaining messages, flushes librdkafka queue
 *
 * Note: Batching is handled by librdkafka internally via linger.ms setting.
 *       No application-level batching is needed.
 */
static void *KafkaProducerThread(void *arg)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)arg;

    SCSetThreadName("SCKafkaProd");

    SCLogInfo("Kafka producer thread started");

    while (SC_ATOMIC_GET(ctx->stop_flag) == 0) {
        uint32_t drained = KafkaDrainQueuesInternal(ctx->registry,
                ctx->setup.max_drain_batch, ctx->setup.idle_poll_ms,
                KafkaDrainProduceHook, ctx, KafkaDrainPollHook, ctx);
        if (drained == 0) {
            usleep(1000);
        }
    }

    SCLogInfo("Kafka producer thread: draining remaining messages...");

    /* Close all registered queues to reject new writes, then drain remaining messages */
    KafkaQueueRegistryCloseAll(ctx->registry);

    /* Drain remaining messages in passes until all queues are empty */
    uint32_t remaining = 0;
    uint32_t pass = 0;
    while (1) {
        uint32_t drained = KafkaDrainQueuesInternal(ctx->registry,
                ctx->setup.max_drain_batch, ctx->setup.idle_poll_ms,
                KafkaDrainProduceHook, ctx, KafkaDrainPollHook, ctx);
        remaining += drained;
        if (drained == 0)
            break;
        pass++;
    }
    SCLogNotice("Kafka: producer thread drained %u remaining messages in %u passes",
            remaining, pass);

    /* Wait for librdkafka internal queue to drain */
    SCLogInfo("Kafka producer thread: flushing librdkafka queue...");
    rd_kafka_flush(ctx->rk, 10000);  /* 10 second timeout */

    SCLogInfo("Kafka producer thread: exiting");
    return NULL;
}

/**
 * \brief Initialize Kafka output
 */
static int KafkaInit(const SCConfNode *conf, const bool threaded, void **init_data)
{
    /* Find kafka configuration node */
    const SCConfNode *kafka_node = SCConfNodeLookupChild(conf, "kafka");
    if (kafka_node == NULL) {
        SCLogError("Kafka: 'kafka' configuration node not found");
        return -1;
    }

    /* Validate required configuration */
    const char *brokers = SCConfNodeLookupChildValue(kafka_node, "brokers");
    if (brokers == NULL) {
        SCLogError("Kafka: 'brokers' configuration required");
        return -1;
    }

    const char *topic = SCConfNodeLookupChildValue(kafka_node, "topic");
    if (topic == NULL) {
        SCLogError("Kafka: 'topic' configuration required");
        return -1;
    }

    SCEveKafkaContext *ctx = SCCalloc(1, sizeof(*ctx));
    if (!ctx) {
        SCLogError("Kafka: Failed to allocate context");
        return -1;
    }

    /* Parse configuration */
    if (KafkaParseConfig(kafka_node, &ctx->setup) != 0) {
        goto error;
    }

    /* Create queue registry for per-thread queues */
    ctx->registry = KafkaQueueRegistryCreate();
    if (ctx->registry == NULL) {
        FatalError("Kafka: Failed to create queue registry");
    }

    /* Create librdkafka configuration */
    rd_kafka_conf_t *rk_conf = KafkaCreateRdKafkaConf(&ctx->setup);
    if (!rk_conf) {
        SCLogError("Kafka: Failed to create librdkafka configuration");
        goto error;
    }

    /* Set opaque pointer for callbacks */
    rd_kafka_conf_set_opaque(rk_conf, ctx);

    /* Create producer */
    char errbuf[512];
    ctx->rk = rd_kafka_new(RD_KAFKA_PRODUCER, rk_conf, errbuf, sizeof(errbuf));
    if (!ctx->rk) {
        SCLogError("Kafka: Failed to create producer: %s", errbuf);
        rd_kafka_conf_destroy(rk_conf);
        goto error;
    }

    if (KafkaMaybeCreateTopic(&ctx->setup, ctx->setup.topic, KafkaCreateTopicHook, ctx) != 0) {
        SCLogWarning("Kafka: topic creation failed for %s (may already exist)", ctx->setup.topic);
    }

    /* Initialize atomic statistics - must be done before thread starts */
    SC_ATOMIC_INIT(ctx->messages_sent);
    SC_ATOMIC_INIT(ctx->messages_failed);
    SC_ATOMIC_INIT(ctx->messages_dropped);
    SC_ATOMIC_INIT(ctx->messages_dropped_queue);
    SC_ATOMIC_INIT(ctx->messages_dropped_produce);
    SC_ATOMIC_INIT(ctx->bytes_sent);
    SC_ATOMIC_INIT(ctx->messages_queued);
    SC_ATOMIC_INIT(ctx->bytes_queued);
    SC_ATOMIC_INIT(ctx->delivery_callback_count);
    SC_ATOMIC_INIT(ctx->stop_flag);
    SC_ATOMIC_SET(ctx->stop_flag, 0);

    /* Start producer thread */
    if (pthread_create(&ctx->producer_thread, NULL, KafkaProducerThread, ctx) != 0) {
        SCLogError("Kafka: Failed to create producer thread");
        goto error;
    }

#ifdef HAVE_PTHREAD_SETNAME_NP
    pthread_setname_np(ctx->producer_thread, "SCKafkaProd");
#endif

    *init_data = ctx;
    SCLogNotice("Kafka producer initialized (brokers: %s, topic: %s, ring_buffer_size: %d, "
                "ring_buffer_max_bytes: %" PRIu64 ", queue_buffering_max_kbytes: %d, linger_ms: %dms)",
            ctx->setup.brokers, ctx->setup.topic, ctx->setup.ring_buffer_size,
            ctx->setup.ring_buffer_max_bytes, ctx->setup.queue_buffering_max_kbytes,
            ctx->setup.linger_ms);
    return 0;

error:
    if (ctx->registry) {
        KafkaQueueRegistryDestroy(ctx->registry);
    }
    if (ctx->rk) rd_kafka_destroy(ctx->rk);
    KafkaFreeConfig(&ctx->setup);
    SCFree(ctx);
    return -1;
}

/**
 * \brief Deinitialize Kafka output
 */
static void KafkaDeinit(void *init_data)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)init_data;
    if (ctx == NULL) return;

    SCLogInfo("Kafka: Initiating shutdown...");

    /* Signal producer thread to stop */
    SC_ATOMIC_SET(ctx->stop_flag, 1);

    /* Wait for producer thread to finish */
    pthread_join(ctx->producer_thread, NULL);

    /* Destroy producer */
    rd_kafka_destroy(ctx->rk);

    /* Destroy queue registry (also destroys per-thread queues) */
    KafkaQueueRegistryDestroy(ctx->registry);

    /* Free configuration */
    KafkaFreeConfig(&ctx->setup);

    /* Log comprehensive shutdown statistics */
    uint64_t queued = SC_ATOMIC_GET(ctx->messages_queued);
    uint64_t sent = SC_ATOMIC_GET(ctx->messages_sent);
    uint64_t failed = SC_ATOMIC_GET(ctx->messages_failed);
    uint64_t dropped_queue = SC_ATOMIC_GET(ctx->messages_dropped_queue);
    uint64_t dropped_produce = SC_ATOMIC_GET(ctx->messages_dropped_produce);
    uint64_t dropped_total = dropped_queue + dropped_produce;
    uint64_t bytes = SC_ATOMIC_GET(ctx->bytes_sent);

    SCLogNotice("Kafka: shutdown stats: queued=%" PRIu64 " sent=%" PRIu64
                " failed=%" PRIu64 " dropped_queue=%" PRIu64
                " dropped_produce=%" PRIu64 " dropped_total=%" PRIu64
                " bytes=%" PRIu64,
            queued, sent, failed, dropped_queue, dropped_produce, dropped_total, bytes);

    SCFree(ctx);
}

/**
 * \brief Write JSON event to queue
 */
static int KafkaWrite(const char *buffer, const int buffer_len,
                      const void *init_data, void *thread_data)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)init_data;
    SCEveKafkaThreadData *td = (SCEveKafkaThreadData *)thread_data;
    if (ctx == NULL || td == NULL || td->queue == NULL || buffer == NULL || buffer_len <= 0) {
        return 0;
    }

    char *data = SCMalloc((size_t)buffer_len + 1);
    if (data == NULL) {
        SC_ATOMIC_ADD(ctx->messages_dropped_queue, 1);
        return 0;
    }
    memcpy(data, buffer, (size_t)buffer_len);
    data[buffer_len] = '\0';

    KafkaQueuePushResult ret = KafkaQueuePush(td->queue, (const uint8_t *)data, (size_t)buffer_len);
    if (ret == KAFKA_QUEUE_PUSH_OK) {
        SC_ATOMIC_ADD(ctx->messages_queued, 1);
        SC_ATOMIC_ADD(ctx->bytes_queued, (uint64_t)buffer_len);
    } else {
        SC_ATOMIC_ADD(ctx->messages_dropped_queue, 1);
    }
    SCFree(data);
    return 0;
}

/**
 * \brief Thread-specific initialization
 */
static int KafkaThreadInit(const void *init_data, const ThreadId thread_id, void **thread_data)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)init_data;
    SCEveKafkaThreadData *td = SCCalloc(1, sizeof(*td));
    if (td == NULL) {
        return -1;
    }

    td->queue = KafkaQueueCreate(
            (uint32_t)ctx->setup.ring_buffer_size, ctx->setup.ring_buffer_max_bytes);
    if (td->queue == NULL) {
        SCFree(td);
        return -1;
    }
    if (KafkaQueueRegistryRegister(ctx->registry, td->queue) != 0) {
        KafkaQueueDestroy(td->queue);
        SCFree(td);
        return -1;
    }

    *thread_data = td;
    return 0;
}

/**
 * \brief Thread-specific deinitialization
 */
static void KafkaThreadDeinit(const void *init_data, void *thread_data)
{
    SCEveKafkaThreadData *td = (SCEveKafkaThreadData *)thread_data;
    if (td == NULL) {
        return;
    }
    KafkaQueueClose(td->queue);
    SCFree(td);
}

#ifdef UNITTESTS

static SCConfNode *KafkaTestCreateBaseConfig(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF_NOT(SCConfSet("kafka.brokers", "127.0.0.1:9092"));
    FAIL_IF_NOT(SCConfSet("kafka.topic", "eve"));

    return SCConfGetNode("kafka");
}

static void KafkaTestDestroyBaseConfig(KafkaSetup *setup)
{
    KafkaFreeConfig(setup);
    SCConfDeInit();
    SCConfRestoreContextBackup();
}

static int KafkaTestParseConfigDefaults(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) != 0);
    FAIL_IF(setup.ring_buffer_max_bytes != KAFKA_RING_BUFFER_MAX_BYTES);
    FAIL_IF(setup.reconnect_backoff_ms != KAFKA_RECONNECT_BACKOFF_MS);
    FAIL_IF(setup.reconnect_backoff_max_ms != KAFKA_RECONNECT_BACKOFF_MAX_MS);
    FAIL_IF(setup.retry_backoff_max_ms != KAFKA_RETRY_BACKOFF_MAX_MS);
    FAIL_IF(setup.queue_buffering_max_kbytes != KAFKA_QUEUE_BUFFERING_MAX_KBYTES);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigInvalidRingBufferMaxBytes(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.ring-buffer-max-bytes", "0"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) == 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigInvalidRingBufferSize(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.ring-buffer-size", "1"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) == 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigInvalidPartition(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.partition", "-2"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) == 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigInvalidReconnectBackoffOrder(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.reconnect-backoff-ms", "200"));
    FAIL_IF_NOT(SCConfSet("kafka.reconnect-backoff-max-ms", "100"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) == 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigInvalidRetryBackoffOrder(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.retry-backoff-ms", "200"));
    FAIL_IF_NOT(SCConfSet("kafka.retry-backoff-max-ms", "100"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) == 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigValidRetryBackoffZero(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.retry-backoff-ms", "0"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) != 0);
    FAIL_IF(setup.retry_backoff_ms != 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestQueueFullRetryBudget(void)
{
    FAIL_IF_NOT(KafkaQueueFullRetryBudget(0));
    FAIL_IF_NOT(KafkaQueueFullRetryBudget(1));
    FAIL_IF_NOT(KafkaQueueFullRetryBudget(2));
    FAIL_IF(KafkaQueueFullRetryBudget(3));
    FAIL_IF(KafkaQueueFullRetryBudget(4));
    PASS;
}

static int KafkaTestShouldRetryQueueFull(void)
{
    FAIL_IF_NOT(KafkaShouldRetryQueueFull(RD_KAFKA_RESP_ERR__QUEUE_FULL, 0));
    FAIL_IF_NOT(KafkaShouldRetryQueueFull(RD_KAFKA_RESP_ERR__QUEUE_FULL, 1));
    FAIL_IF_NOT(KafkaShouldRetryQueueFull(RD_KAFKA_RESP_ERR__QUEUE_FULL, 2));
    FAIL_IF(KafkaShouldRetryQueueFull(RD_KAFKA_RESP_ERR__QUEUE_FULL, 3));
    FAIL_IF(KafkaShouldRetryQueueFull(RD_KAFKA_RESP_ERR__QUEUE_FULL, 4));
    FAIL_IF(KafkaShouldRetryQueueFull(RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC, 0));
    PASS;
}

typedef struct KafkaTestProduceHooksCtx_ {
    rd_kafka_resp_err_t sequence[8];
    uint32_t sequence_len;
    uint32_t produce_calls;
    uint32_t poll_calls;
} KafkaTestProduceHooksCtx;

static rd_kafka_resp_err_t KafkaTestProduceHook(
        void *ctx, const char *topic, char *data, const size_t len)
{
    KafkaTestProduceHooksCtx *tctx = (KafkaTestProduceHooksCtx *)ctx;
    (void)topic;
    (void)data;
    (void)len;

    uint32_t idx = tctx->produce_calls;
    tctx->produce_calls++;
    if (idx >= tctx->sequence_len) {
        idx = tctx->sequence_len - 1;
    }
    return tctx->sequence[idx];
}

static void KafkaTestPollHook(void *ctx, const int timeout_ms)
{
    KafkaTestProduceHooksCtx *tctx = (KafkaTestProduceHooksCtx *)ctx;
    (void)timeout_ms;
    tctx->poll_calls++;
}

static int KafkaTestProduceWithRetryInternalQueueFullBeyondBudget(void)
{
    KafkaTestProduceHooksCtx tctx = {
        .sequence = { RD_KAFKA_RESP_ERR__QUEUE_FULL, RD_KAFKA_RESP_ERR__QUEUE_FULL,
                RD_KAFKA_RESP_ERR__QUEUE_FULL, RD_KAFKA_RESP_ERR__QUEUE_FULL },
        .sequence_len = 4,
        .produce_calls = 0,
        .poll_calls = 0,
    };
    uint32_t retries = 0;
    rd_kafka_resp_err_t ret = KafkaProduceWithRetryInternal(&tctx, "eve", NULL, 0,
            KafkaTestProduceHook, KafkaTestPollHook, &retries);
    FAIL_IF(ret != RD_KAFKA_RESP_ERR__QUEUE_FULL);
    FAIL_IF(retries != KAFKA_QUEUE_FULL_RETRY_MAX);
    FAIL_IF(tctx.poll_calls != KAFKA_QUEUE_FULL_RETRY_MAX);
    FAIL_IF(tctx.produce_calls != (KAFKA_QUEUE_FULL_RETRY_MAX + 1));
    PASS;
}

static int KafkaTestProduceWithRetryInternalQueueFullThenSuccess(void)
{
    KafkaTestProduceHooksCtx tctx = {
        .sequence = { RD_KAFKA_RESP_ERR__QUEUE_FULL, RD_KAFKA_RESP_ERR__QUEUE_FULL,
                RD_KAFKA_RESP_ERR_NO_ERROR },
        .sequence_len = 3,
        .produce_calls = 0,
        .poll_calls = 0,
    };
    uint32_t retries = 0;
    rd_kafka_resp_err_t ret = KafkaProduceWithRetryInternal(&tctx, "eve", NULL, 0,
            KafkaTestProduceHook, KafkaTestPollHook, &retries);
    FAIL_IF(ret != RD_KAFKA_RESP_ERR_NO_ERROR);
    FAIL_IF(retries != 2);
    FAIL_IF(tctx.poll_calls != 2);
    FAIL_IF(tctx.produce_calls != 3);
    PASS;
}

static int KafkaTestProduceWithRetryInternalNonQueueFullImmediateError(void)
{
    KafkaTestProduceHooksCtx tctx = {
        .sequence = { RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC },
        .sequence_len = 1,
        .produce_calls = 0,
        .poll_calls = 0,
    };
    uint32_t retries = 0;
    rd_kafka_resp_err_t ret = KafkaProduceWithRetryInternal(&tctx, "eve", NULL, 0,
            KafkaTestProduceHook, KafkaTestPollHook, &retries);
    FAIL_IF(ret != RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC);
    FAIL_IF(retries != 0);
    FAIL_IF(tctx.poll_calls != 0);
    FAIL_IF(tctx.produce_calls != 1);
    PASS;
}

static int KafkaTestParseConfigHighThroughputDefaults(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) != 0);

    FAIL_IF(setup.partition != RD_KAFKA_PARTITION_UA);
    FAIL_IF(setup.topic_auto_create != false);
    FAIL_IF(setup.topic_partitions != 1);
    FAIL_IF(setup.max_drain_batch != 256);
    FAIL_IF(setup.idle_poll_ms != 10);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigTopicAutoCreateEnabled(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.topic-auto-create", "yes"));
    FAIL_IF_NOT(SCConfSet("kafka.topic-partitions", "12"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) != 0);
    FAIL_IF(setup.topic_auto_create != true);
    FAIL_IF(setup.topic_partitions != 12);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigInvalidIntOverflow(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.max-drain-batch", "2147483648"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) == 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestParseConfigInvalidTopicPartitions(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.topic-partitions", "0"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) == 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}

static int KafkaTestQueueBasicPushPop(void)
{
    SCEveKafkaQueue *queue = KafkaQueueCreate(8, 1024);
    FAIL_IF_NULL(queue);

    uint8_t data[] = "hello";
    FAIL_IF(KafkaQueuePush(queue, data, sizeof(data)) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(queue->count != 1);
    FAIL_IF(queue->pushed != 1);

    SCEveKafkaQueueEntry *entry = KafkaQueuePop(queue);
    FAIL_IF_NULL(entry);
    FAIL_IF(entry->len != sizeof(data));
    FAIL_IF(memcmp(entry->data, data, sizeof(data)) != 0);
    FAIL_IF(queue->popped != 1);

    SCFree(entry->data);
    SCFree(entry);
    KafkaQueueDestroy(queue);
    PASS;
}

static int KafkaTestQueueCountBudgetDropOldest(void)
{
    SCEveKafkaQueue *queue = KafkaQueueCreate(4, 1024 * 1024);
    FAIL_IF_NULL(queue);

    for (int i = 0; i < 6; i++) {
        uint8_t data[8];
        data[0] = (uint8_t)i;
        FAIL_IF(KafkaQueuePush(queue, data, sizeof(data)) != KAFKA_QUEUE_PUSH_OK);
    }

    FAIL_IF(queue->count != 4);
    FAIL_IF(queue->dropped != 2);

    SCEveKafkaQueueEntry *entry = KafkaQueuePop(queue);
    FAIL_IF_NULL(entry);
    FAIL_IF(entry->data[0] != 2);
    SCFree(entry->data);
    SCFree(entry);

    KafkaQueueDestroy(queue);
    PASS;
}

static int KafkaTestQueueByteBudgetDropOldest(void)
{
    SCEveKafkaQueue *queue = KafkaQueueCreate(100, 32);
    FAIL_IF_NULL(queue);

    uint8_t payload[16];
    memset(payload, 'A', sizeof(payload));

    FAIL_IF(KafkaQueuePush(queue, payload, sizeof(payload)) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(queue, payload, sizeof(payload)) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(queue->current_bytes != 32);
    FAIL_IF(queue->count != 2);

    FAIL_IF(KafkaQueuePush(queue, payload, sizeof(payload)) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(queue->current_bytes > 32);
    FAIL_IF(queue->dropped != 1);

    KafkaQueueDestroy(queue);
    PASS;
}

static int KafkaTestQueueOversizedDrop(void)
{
    SCEveKafkaQueue *queue = KafkaQueueCreate(100, 16);
    FAIL_IF_NULL(queue);

    uint8_t payload[32];
    memset(payload, 'B', sizeof(payload));
    FAIL_IF(KafkaQueuePush(queue, payload, sizeof(payload)) != KAFKA_QUEUE_PUSH_DROPPED);
    FAIL_IF(queue->count != 0);
    FAIL_IF(queue->dropped != 1);

    KafkaQueueDestroy(queue);
    PASS;
}

static int KafkaTestQueueClosedRejectsWrites(void)
{
    SCEveKafkaQueue *queue = KafkaQueueCreate(8, 1024);
    FAIL_IF_NULL(queue);

    uint8_t data[] = "test";
    FAIL_IF(KafkaQueuePush(queue, data, sizeof(data)) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(queue->count != 1);

    KafkaQueueClose(queue);
    FAIL_IF(KafkaQueuePush(queue, data, sizeof(data)) != KAFKA_QUEUE_PUSH_CLOSED);

    SCEveKafkaQueueEntry *entry = KafkaQueuePop(queue);
    FAIL_IF_NULL(entry);
    FAIL_IF(entry->len != sizeof(data));
    SCFree(entry->data);
    SCFree(entry);

    entry = KafkaQueuePop(queue);
    FAIL_IF_NOT_NULL(entry);

    KafkaQueueDestroy(queue);
    PASS;
}

static int KafkaTestQueueRegistryRegistersMultipleQueues(void)
{
    SCEveKafkaQueueRegistry *registry = KafkaQueueRegistryCreate();
    FAIL_IF_NULL(registry);

    SCEveKafkaQueue *q0 = KafkaQueueCreate(4, 64);
    SCEveKafkaQueue *q1 = KafkaQueueCreate(4, 64);
    FAIL_IF_NULL(q0);
    FAIL_IF_NULL(q1);
    FAIL_IF(KafkaQueueRegistryRegister(registry, q0) != 0);
    FAIL_IF(KafkaQueueRegistryRegister(registry, q1) != 0);
    FAIL_IF(registry->queue_count != 2);

    KafkaQueueRegistryDestroy(registry);
    PASS;
}

static int KafkaTestKafkaWriteUsesThreadQueue(void)
{
    SCEveKafkaContext ctx = { 0 };
    SC_ATOMIC_INIT(ctx.messages_queued);
    SC_ATOMIC_INIT(ctx.messages_dropped_queue);
    SC_ATOMIC_INIT(ctx.bytes_queued);

    SCEveKafkaQueue *q = KafkaQueueCreate(4, 64);
    FAIL_IF_NULL(q);
    SCEveKafkaThreadData td = { .queue = q };

    FAIL_IF(KafkaWrite("{\"event_type\":\"alert\"}", 22, &ctx, &td) != 0);
    FAIL_IF(SC_ATOMIC_GET(ctx.messages_queued) != 1);
    FAIL_IF(SC_ATOMIC_GET(ctx.bytes_queued) != 22);

    SCEveKafkaQueueEntry *entry = KafkaQueuePop(q);
    FAIL_IF_NULL(entry);
    FAIL_IF(entry->len != 22);
    SCFree(entry->data);
    SCFree(entry);

    KafkaQueueDestroy(q);
    PASS;
}

typedef struct KafkaTestDrainCtx_ {
    uint8_t *produced[16];
    size_t produced_lens[16];
    uint32_t produced_count;
    int32_t poll_timeouts[16];
    uint32_t poll_count;
} KafkaTestDrainCtx;

static rd_kafka_resp_err_t KafkaTestDrainProduceHook(void *ctx, const char *topic,
        int32_t partition, const uint8_t *data, size_t len, const void *key, size_t key_len)
{
    KafkaTestDrainCtx *dctx = (KafkaTestDrainCtx *)ctx;
    (void)topic;
    (void)partition;
    (void)key;
    (void)key_len;

    uint8_t *copy = SCMalloc(len);
    if (copy) {
        memcpy(copy, data, len);
    }
    dctx->produced[dctx->produced_count] = copy;
    dctx->produced_lens[dctx->produced_count] = len;
    dctx->produced_count++;
    return RD_KAFKA_RESP_ERR_NO_ERROR;
}

static int KafkaTestDrainPollHook(void *ctx, void *rk, int timeout_ms)
{
    KafkaTestDrainCtx *dctx = (KafkaTestDrainCtx *)ctx;
    (void)rk;
    dctx->poll_timeouts[dctx->poll_count++] = timeout_ms;
    return 0;
}

static int KafkaTestDrainRoundRobinFairness(void)
{
    SCEveKafkaQueueRegistry *registry = KafkaQueueRegistryCreate();
    FAIL_IF_NULL(registry);

    SCEveKafkaQueue *q0 = KafkaQueueCreate(8, 1024);
    FAIL_IF_NULL(q0);
    SCEveKafkaQueue *q1 = KafkaQueueCreate(8, 1024);
    FAIL_IF_NULL(q1);

    FAIL_IF(KafkaQueueRegistryRegister(registry, q0) != 0);
    FAIL_IF(KafkaQueueRegistryRegister(registry, q1) != 0);

    uint8_t data0[] = "aaa";
    uint8_t data1[] = "bbb";
    uint8_t data2[] = "ccc";
    FAIL_IF(KafkaQueuePush(q0, data0, sizeof(data0)) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(q0, data1, sizeof(data1)) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(q1, data2, sizeof(data2)) != KAFKA_QUEUE_PUSH_OK);

    KafkaTestDrainCtx dctx = { 0 };
    uint32_t drained = KafkaDrainQueuesInternal(registry, 1, 10,
            KafkaTestDrainProduceHook, &dctx, KafkaTestDrainPollHook, &dctx);

    FAIL_IF(drained != 2);
    FAIL_IF(dctx.produced_count != 2);
    FAIL_IF(dctx.poll_count != 1);
    FAIL_IF(dctx.poll_timeouts[0] != 0);

    /* q0 had 2 entries, drained 1 (max_batch=1); q1 had 1, drained 1 */
    FAIL_IF(q0->count != 1);
    FAIL_IF(q1->count != 0);

    /* First drain should produce from q0 (index 0), second from q1 (index 1) */
    FAIL_IF(dctx.produced_lens[0] != sizeof(data0));
    FAIL_IF(memcmp(dctx.produced[0], data0, sizeof(data0)) != 0);
    FAIL_IF(dctx.produced_lens[1] != sizeof(data2));
    FAIL_IF(memcmp(dctx.produced[1], data2, sizeof(data2)) != 0);

    SCFree(dctx.produced[0]);
    SCFree(dctx.produced[1]);
    KafkaQueueDestroy(q0);
    KafkaQueueDestroy(q1);
    SCFree(registry->queues);
    SCMutexDestroy(&registry->lock);
    SCFree(registry);
    PASS;
}

static int KafkaTestDrainIdlePollsWithTimeout(void)
{
    SCEveKafkaQueueRegistry *registry = KafkaQueueRegistryCreate();
    FAIL_IF_NULL(registry);

    KafkaTestDrainCtx dctx = { 0 };
    uint32_t drained = KafkaDrainQueuesInternal(registry, 8, 17,
            KafkaTestDrainProduceHook, &dctx, KafkaTestDrainPollHook, &dctx);

    FAIL_IF(drained != 0);
    FAIL_IF(dctx.produced_count != 0);
    FAIL_IF(dctx.poll_count != 1);
    FAIL_IF(dctx.poll_timeouts[0] != 17);

    SCFree(registry->queues);
    SCMutexDestroy(&registry->lock);
    SCFree(registry);
    PASS;
}

typedef struct KafkaTestCreateTopicCtx_ {
    const char *topic;
    int32_t partition_count;
    int call_count;
} KafkaTestCreateTopicCtx;

static int KafkaTestCreateTopicHook(void *ctx, const char *topic, int32_t partition_count)
{
    KafkaTestCreateTopicCtx *tctx = (KafkaTestCreateTopicCtx *)ctx;
    tctx->topic = topic;
    tctx->partition_count = partition_count;
    tctx->call_count++;
    return 0;
}

static int KafkaTestTopicCreateAutoCreateDisabled(void)
{
    KafkaSetup setup = { 0 };
    setup.topic_auto_create = false;
    setup.topic_partitions = 4;

    KafkaTestCreateTopicCtx tctx = { 0 };
    int ret = KafkaMaybeCreateTopic(&setup, "test-topic", KafkaTestCreateTopicHook, &tctx);
    FAIL_IF(ret != 0);
    FAIL_IF(tctx.call_count != 0);
    PASS;
}

static int KafkaTestTopicCreateAutoCreateEnabled(void)
{
    KafkaSetup setup = { 0 };
    setup.topic_auto_create = true;
    setup.topic_partitions = 4;

    KafkaTestCreateTopicCtx tctx = { 0 };
    int ret = KafkaMaybeCreateTopic(&setup, "test-topic", KafkaTestCreateTopicHook, &tctx);
    FAIL_IF(ret != 0);
    FAIL_IF(tctx.call_count != 1);
    FAIL_IF(tctx.partition_count != 4);
    FAIL_IF(strcmp(tctx.topic, "test-topic") != 0);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief Register Kafka EVE output filetype
 */
void SCEveKafkaInitialize(void)
{
    SCEveFileType *file_type = SCCalloc(1, sizeof(SCEveFileType));
    if (file_type == NULL) {
        FatalError("Kafka: Unable to allocate memory for eve file type");
        return;
    }

    file_type->name = OUTPUT_NAME;
    file_type->Init = KafkaInit;
    file_type->Deinit = KafkaDeinit;
    file_type->Write = KafkaWrite;
    file_type->ThreadInit = KafkaThreadInit;
    file_type->ThreadDeinit = KafkaThreadDeinit;

    if (!SCRegisterEveFileType(file_type)) {
        FatalError("Kafka: Failed to register EVE file type: %s", OUTPUT_NAME);
        SCFree(file_type);
        return;
    }

    SCLogNotice("Kafka EVE output registered");

#ifdef UNITTESTS
    UtRegisterTest("KafkaTestParseConfigDefaults", KafkaTestParseConfigDefaults);
    UtRegisterTest("KafkaTestParseConfigInvalidRingBufferMaxBytes",
            KafkaTestParseConfigInvalidRingBufferMaxBytes);
    UtRegisterTest("KafkaTestParseConfigInvalidRingBufferSize",
            KafkaTestParseConfigInvalidRingBufferSize);
    UtRegisterTest("KafkaTestParseConfigInvalidPartition", KafkaTestParseConfigInvalidPartition);
    UtRegisterTest("KafkaTestParseConfigInvalidReconnectBackoffOrder",
            KafkaTestParseConfigInvalidReconnectBackoffOrder);
    UtRegisterTest("KafkaTestParseConfigInvalidRetryBackoffOrder",
            KafkaTestParseConfigInvalidRetryBackoffOrder);
    UtRegisterTest("KafkaTestParseConfigValidRetryBackoffZero",
            KafkaTestParseConfigValidRetryBackoffZero);
    UtRegisterTest("KafkaTestQueueFullRetryBudget", KafkaTestQueueFullRetryBudget);
    UtRegisterTest("KafkaTestShouldRetryQueueFull", KafkaTestShouldRetryQueueFull);
    UtRegisterTest("KafkaTestProduceWithRetryInternalQueueFullBeyondBudget",
            KafkaTestProduceWithRetryInternalQueueFullBeyondBudget);
    UtRegisterTest("KafkaTestProduceWithRetryInternalQueueFullThenSuccess",
            KafkaTestProduceWithRetryInternalQueueFullThenSuccess);
    UtRegisterTest("KafkaTestProduceWithRetryInternalNonQueueFullImmediateError",
            KafkaTestProduceWithRetryInternalNonQueueFullImmediateError);
    UtRegisterTest("KafkaTestParseConfigHighThroughputDefaults",
            KafkaTestParseConfigHighThroughputDefaults);
    UtRegisterTest("KafkaTestParseConfigTopicAutoCreateEnabled",
            KafkaTestParseConfigTopicAutoCreateEnabled);
    UtRegisterTest("KafkaTestParseConfigInvalidIntOverflow",
            KafkaTestParseConfigInvalidIntOverflow);
    UtRegisterTest("KafkaTestParseConfigInvalidTopicPartitions",
            KafkaTestParseConfigInvalidTopicPartitions);
    UtRegisterTest("KafkaTestQueueBasicPushPop", KafkaTestQueueBasicPushPop);
    UtRegisterTest("KafkaTestQueueCountBudgetDropOldest", KafkaTestQueueCountBudgetDropOldest);
    UtRegisterTest("KafkaTestQueueByteBudgetDropOldest", KafkaTestQueueByteBudgetDropOldest);
    UtRegisterTest("KafkaTestQueueOversizedDrop", KafkaTestQueueOversizedDrop);
    UtRegisterTest("KafkaTestQueueClosedRejectsWrites", KafkaTestQueueClosedRejectsWrites);
    UtRegisterTest("KafkaTestQueueRegistryRegistersMultipleQueues",
            KafkaTestQueueRegistryRegistersMultipleQueues);
    UtRegisterTest("KafkaTestKafkaWriteUsesThreadQueue", KafkaTestKafkaWriteUsesThreadQueue);
    UtRegisterTest("KafkaTestDrainRoundRobinFairness", KafkaTestDrainRoundRobinFairness);
    UtRegisterTest("KafkaTestDrainIdlePollsWithTimeout", KafkaTestDrainIdlePollsWithTimeout);
    UtRegisterTest("KafkaTestTopicCreateAutoCreateDisabled", KafkaTestTopicCreateAutoCreateDisabled);
    UtRegisterTest("KafkaTestTopicCreateAutoCreateEnabled", KafkaTestTopicCreateAutoCreateEnabled);
#endif
}

#else /* !HAVE_LIBRDKAFKA */

void SCEveKafkaInitialize(void)
{
    SCLogNotice("Kafka EVE output support not compiled in (librdkafka not found)");
}

#endif /* HAVE_LIBRDKAFKA */
