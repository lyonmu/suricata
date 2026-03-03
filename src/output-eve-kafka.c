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
 * It uses a ring buffer for decoupling Suricata's packet processing
 * from Kafka message production, ensuring that Kafka failures do not
 * affect packet processing performance.
 *
 * \note Ring buffer overwrites oldest messages when full.
 * This may cause out-of-order delivery during high load.
 * For strict ordering, increase ring_buffer_size.
 */

#include "suricata-common.h"
#include "output-eve.h"
#include "output-eve-kafka.h"
#include "conf.h"
#include "util-debug.h"
#include "util-unittest.h"

#ifdef HAVE_LIBRDKAFKA

#include <librdkafka/rdkafka.h>

#define OUTPUT_NAME "kafka"

/* Forward declarations */
static void *KafkaProducerThread(void *arg);
static void KafkaDeliveryReportCallback(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque);
static void KafkaLogCallback(const rd_kafka_t *rk, int level, const char *fac, const char *buf);

/**
 * \brief Initialize ring buffer with specified size
 */
static SCEveKafkaRingBuffer *RingBufferInit(uint32_t size)
{
    if (size == 0) {
        SCLogError("Ring buffer size must be > 0");
        return NULL;
    }

    SCEveKafkaRingBuffer *rb = SCCalloc(1, sizeof(*rb));
    if (rb == NULL) {
        return NULL;
    }

    rb->entries = SCCalloc(size, sizeof(SCEveKafkaRingBufferEntry));
    if (rb->entries == NULL) {
        SCFree(rb);
        return NULL;
    }

    rb->size = size;
    rb->head = 0;
    rb->tail = 0;
    SC_ATOMIC_INIT(rb->dropped);
    SC_ATOMIC_INIT(rb->pushed);
    SC_ATOMIC_INIT(rb->popped);
    SCSpinInit(&rb->lock, 0);

    SCLogInfo("Kafka ring buffer initialized with size %u", size);
    return rb;
}

/**
 * \brief Push message to ring buffer
 */
static int RingBufferPush(SCEveKafkaRingBuffer *rb, char *data, size_t len)
{
    DEBUG_VALIDATE_BUG_ON(rb == NULL);
    DEBUG_VALIDATE_BUG_ON(data == NULL);

    SCSpinLock(&rb->lock);

    uint32_t next_head = (rb->head + 1) % rb->size;

    /* Check if buffer is full - overwrite oldest */
    if (next_head == rb->tail) {
        SCEveKafkaRingBufferEntry *old_entry = &rb->entries[rb->tail];
        if (old_entry->data != NULL) {
            SCFree(old_entry->data);
            old_entry->data = NULL;
            old_entry->len = 0;
            SC_ATOMIC_ADD(rb->dropped, 1);
        }
        rb->tail = (rb->tail + 1) % rb->size;
    }

    /* Add new entry at head */
    SCEveKafkaRingBufferEntry *entry = &rb->entries[rb->head];
    entry->data = data;
    entry->len = len;
    rb->head = next_head;

    SC_ATOMIC_ADD(rb->pushed, 1);

    SCSpinUnlock(&rb->lock);
    return 0;
}

/**
 * \brief Pop single message from ring buffer
 */
static int RingBufferPop(SCEveKafkaRingBuffer *rb, SCEveKafkaRingBufferEntry *entry)
{
    DEBUG_VALIDATE_BUG_ON(rb == NULL);
    DEBUG_VALIDATE_BUG_ON(entry == NULL);

    int ret = -1;

    SCSpinLock(&rb->lock);

    if (rb->head != rb->tail) {
        entry->data = rb->entries[rb->tail].data;
        entry->len = rb->entries[rb->tail].len;

        rb->entries[rb->tail].data = NULL;
        rb->entries[rb->tail].len = 0;

        rb->tail = (rb->tail + 1) % rb->size;

        SC_ATOMIC_ADD(rb->popped, 1);
        ret = 0;
    }

    SCSpinUnlock(&rb->lock);
    return ret;
}

/**
 * \brief Destroy ring buffer
 */
static void RingBufferDestroy(SCEveKafkaRingBuffer *rb)
{
    if (rb == NULL) return;

    SCLogInfo("Kafka ring buffer destroying (dropped: %"PRIu64", pushed: %"PRIu64", popped: %"PRIu64")",
              SC_ATOMIC_GET(rb->dropped),
              SC_ATOMIC_GET(rb->pushed),
              SC_ATOMIC_GET(rb->popped));

    for (uint32_t i = 0; i < rb->size; i++) {
        if (rb->entries[i].data != NULL) {
            SCFree(rb->entries[i].data);
            rb->entries[i].data = NULL;
            rb->entries[i].len = 0;
        }
    }

    SCFree(rb->entries);
    SCSpinDestroy(&rb->lock);
    SCFree(rb);
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
    setup->brokers = SCStrdup(val);

    val = SCConfNodeLookupChildValue(conf, "topic");
    if (val == NULL) {
        SCLogError("Kafka: 'topic' configuration required");
        return -1;
    }
    setup->topic = SCStrdup(val);

    /* Optional settings with defaults */
    val = SCConfNodeLookupChildValue(conf, "client-id");
    setup->client_id = val ? SCStrdup(val) : SCStrdup("suricata");

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
    setup->partition = -1;  /* Automatic partitioning */
    setup->ring_buffer_size = KAFKA_RING_BUFFER_SIZE_DEFAULT;

    /* librdkafka internal queue settings with defaults */
    setup->queue_buffering_max_messages = KAFKA_QUEUE_BUFFERING_MAX_MSGS;
    setup->queue_buffering_max_kbytes = KAFKA_QUEUE_BUFFERING_MAX_KBYTES;
    setup->message_timeout_ms = KAFKA_MESSAGE_TIMEOUT_MS;
    setup->socket_timeout_ms = KAFKA_SOCKET_TIMEOUT_MS;
    setup->metadata_max_age_ms = KAFKA_METADATA_MAX_AGE_MS;
    setup->retry_backoff_ms = KAFKA_RETRY_BACKOFF_MS;
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
    if (SCConfGetChildValueInt(conf, "partition", &intval)) {
        setup->partition = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "ring-buffer-size", &intval)) {
        setup->ring_buffer_size = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "queue-buffering-max-messages", &intval)) {
        setup->queue_buffering_max_messages = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "queue-buffering-max-kbytes", &intval)) {
        setup->queue_buffering_max_kbytes = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "message-timeout-ms", &intval)) {
        setup->message_timeout_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "socket-timeout-ms", &intval)) {
        setup->socket_timeout_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "metadata-max-age-ms", &intval)) {
        setup->metadata_max_age_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "retry-backoff-ms", &intval)) {
        setup->retry_backoff_ms = (int)intval;
    }
    if (SCConfGetChildValueInt(conf, "linger-ms", &intval)) {
        setup->linger_ms = (int)intval;
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
    if (val != NULL) setup->ssl_ca_location = SCStrdup(val);

    val = SCConfNodeLookupChildValue(conf, "ssl-certificate-location");
    if (val != NULL) setup->ssl_certificate_location = SCStrdup(val);

    val = SCConfNodeLookupChildValue(conf, "ssl-key-location");
    if (val != NULL) setup->ssl_key_location = SCStrdup(val);

    val = SCConfNodeLookupChildValue(conf, "ssl-key-password");
    if (val != NULL) setup->ssl_key_password = SCStrdup(val);

    /* SASL settings */
    val = SCConfNodeLookupChildValue(conf, "sasl-mechanism");
    if (val != NULL) setup->sasl_mechanism = SCStrdup(val);

    val = SCConfNodeLookupChildValue(conf, "sasl-username");
    if (val != NULL) setup->sasl_username = SCStrdup(val);

    val = SCConfNodeLookupChildValue(conf, "sasl-password");
    if (val != NULL) setup->sasl_password = SCStrdup(val);

    return 0;
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
    /* Use -1 for replication_factor to let broker use default (librdkafka 2.4.0+) */
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

/**
 * \brief Background producer thread
 *
 * Thread lifecycle:
 * 1. Named "SCKafkaProd" via SCSetThreadName() for debugging
 * 2. Loops until stop_flag is set or Suricata shutdown signal
 * 3. Pops messages from ring buffer and produces to Kafka immediately
 * 4. Calls rd_kafka_poll() regularly to trigger delivery callbacks
 * 5. On exit: drains ring buffer, flushes librdkafka queue
 *
 * Note: Batching is handled by librdkafka internally via linger.ms setting.
 *       No application-level batching is needed.
 */
static void *KafkaProducerThread(void *arg)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)arg;

    SCSetThreadName("SCKafkaProd");

    SCLogInfo("Kafka producer thread started");

    while (!ctx->stop_flag) {
        SCEveKafkaRingBufferEntry entry;

        /* Try to get message from ring buffer */
        if (RingBufferPop(ctx->ring_buffer, &entry) == 0) {
            /* Produce message to Kafka immediately */
            rd_kafka_resp_err_t ret = rd_kafka_producev(ctx->rk,
                RD_KAFKA_V_TOPIC(ctx->setup.topic),
                RD_KAFKA_V_VALUE(entry.data, entry.len),
                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_FREE),
                RD_KAFKA_V_KEY(NULL, 0),
                RD_KAFKA_V_END);

            if (ret != RD_KAFKA_RESP_ERR_NO_ERROR) {
                if (ret == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
                    /* Internal queue is full - poll to make room */
                    rd_kafka_poll(ctx->rk, 0);
                    SCLogWarning("Kafka internal queue full, dropping message");
                    SCFree(entry.data);
                    SC_ATOMIC_ADD(ctx->messages_dropped, 1);
                } else {
                    SCLogError("Failed to produce message: %s", rd_kafka_err2str(ret));
                    SCFree(entry.data);
                    SC_ATOMIC_ADD(ctx->messages_dropped, 1);
                }
            }
            /* On success, librdkafka owns entry.data via RD_KAFKA_MSG_F_FREE */
        } else {
            /* No message available - sleep briefly to avoid busy-wait */
            usleep(1000);
        }

        /* Poll for delivery reports - this triggers callbacks */
        rd_kafka_poll(ctx->rk, 100);
    }

    SCLogInfo("Kafka producer thread: draining remaining messages...");

    /* Drain ring buffer - get all remaining messages */
    SCEveKafkaRingBufferEntry entry;
    while (RingBufferPop(ctx->ring_buffer, &entry) == 0) {
        rd_kafka_resp_err_t ret = rd_kafka_producev(ctx->rk,
            RD_KAFKA_V_TOPIC(ctx->setup.topic),
            RD_KAFKA_V_VALUE(entry.data, entry.len),
            RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_FREE),
            RD_KAFKA_V_KEY(NULL, 0),
            RD_KAFKA_V_END);

        if (ret != RD_KAFKA_RESP_ERR_NO_ERROR) {
            SCLogError("Failed to produce final message: %s", rd_kafka_err2str(ret));
            SCFree(entry.data);
            SC_ATOMIC_ADD(ctx->messages_dropped, 1);
        }
    }

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

    /* Initialize ring buffer */
    ctx->ring_buffer = RingBufferInit(ctx->setup.ring_buffer_size);
    if (!ctx->ring_buffer) {
        SCLogError("Kafka: Failed to initialize ring buffer");
        goto error;
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

    /* Create topic with specified partition count */
    if (KafkaCreateTopic(ctx->rk, ctx->setup.topic, ctx->setup.partition, 10000) != 0) {
        SCLogError("Kafka: Failed to create topic '%s'", ctx->setup.topic);
        goto error;
    }

    /* Initialize atomic statistics */
    SC_ATOMIC_INIT(ctx->messages_sent);
    SC_ATOMIC_INIT(ctx->messages_failed);
    SC_ATOMIC_INIT(ctx->messages_dropped);
    SC_ATOMIC_INIT(ctx->bytes_sent);
    SC_ATOMIC_INIT(ctx->delivery_callback_count);

    /* Start producer thread */
    ctx->stop_flag = 0;
    if (pthread_create(&ctx->producer_thread, NULL, KafkaProducerThread, ctx) != 0) {
        SCLogError("Kafka: Failed to create producer thread");
        goto error;
    }

#ifdef HAVE_PTHREAD_SETNAME_NP
    pthread_setname_np(ctx->producer_thread, "SCKafkaProd");
#endif

    *init_data = ctx;
    SCLogNotice("Kafka producer initialized (brokers: %s, topic: %s, ring_buffer_size: %d, linger_ms: %dms)",
                ctx->setup.brokers, ctx->setup.topic, ctx->setup.ring_buffer_size,
                ctx->setup.linger_ms);
    return 0;

error:
    if (ctx->rk) rd_kafka_destroy(ctx->rk);
    if (ctx->ring_buffer) RingBufferDestroy(ctx->ring_buffer);
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
    ctx->stop_flag = 1;

    /* Wait for producer thread to finish */
    pthread_join(ctx->producer_thread, NULL);

    /* Destroy ring buffer */
    RingBufferDestroy(ctx->ring_buffer);

    /* Flush librdkafka queue */
    rd_kafka_flush(ctx->rk, 10000);

    /* Destroy producer */
    rd_kafka_destroy(ctx->rk);

    /* Free configuration */
    KafkaFreeConfig(&ctx->setup);

    /* Log final statistics */
    SCLogInfo("Kafka: Shutdown complete. Sent: %"PRIu64", Failed: %"PRIu64", Dropped: %"PRIu64,
              SC_ATOMIC_GET(ctx->messages_sent),
              SC_ATOMIC_GET(ctx->messages_failed),
              SC_ATOMIC_GET(ctx->messages_dropped));

    SCFree(ctx);
}

/**
 * \brief Write JSON event to ring buffer
 */
static int KafkaWrite(const char *buffer, const int buffer_len,
                      const void *init_data, void *thread_data)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)init_data;
    if (ctx == NULL || ctx->ring_buffer == NULL) {
        return 0;
    }

    /* Allocate copy of data */
    char *data = SCMalloc(buffer_len + 1);
    if (data == NULL) {
        SC_ATOMIC_ADD(ctx->messages_dropped, 1);
        return 0;
    }
    memcpy(data, buffer, buffer_len);
    data[buffer_len] = '\0';

    /* Push to ring buffer */
    int ret = RingBufferPush(ctx->ring_buffer, data, buffer_len);
    if (ret != 0) {
        SCFree(data);
        SC_ATOMIC_ADD(ctx->messages_dropped, 1);
    }

    return 0;
}

/**
 * \brief Thread-specific initialization
 */
static int KafkaThreadInit(const void *init_data, const ThreadId thread_id, void **thread_data)
{
    *thread_data = NULL;
    return 0;
}

/**
 * \brief Thread-specific deinitialization
 */
static void KafkaThreadDeinit(const void *init_data, void *thread_data)
{
}

#ifdef UNITTESTS

static int KafkaTestRingBufferBasic(void)
{
    SCEveKafkaRingBuffer *rb = RingBufferInit(16);
    if (rb == NULL) {
        return 0;
    }

    char *data1 = SCMalloc(10);
    FAIL_IF(data1 == NULL);
    strcpy(data1, "test1");

    char *data2 = SCMalloc(10);
    FAIL_IF(data2 == NULL);
    strcpy(data2, "test2");

    FAIL_IF(RingBufferPush(rb, data1, 6) != 0);
    FAIL_IF(RingBufferPush(rb, data2, 6) != 0);

    SCEveKafkaRingBufferEntry entry;
    FAIL_IF(RingBufferPop(rb, &entry) != 0);
    FAIL_IF(strcmp(entry.data, "test1") != 0);
    SCFree(entry.data);

    FAIL_IF(RingBufferPop(rb, &entry) != 0);
    FAIL_IF(strcmp(entry.data, "test2") != 0);
    SCFree(entry.data);

    FAIL_IF(RingBufferPop(rb, &entry) != -1);

    RingBufferDestroy(rb);
    PASS;
}

static int KafkaTestRingBufferOverflow(void)
{
    SCEveKafkaRingBuffer *rb = RingBufferInit(4);
    if (rb == NULL) {
        return 0;
    }

    for (int i = 0; i < 3; i++) {
        char *data = SCMalloc(10);
        FAIL_IF(data == NULL);
        snprintf(data, 10, "test%d", i);
        FAIL_IF(RingBufferPush(rb, data, 6) != 0);
    }

    char *data = SCMalloc(10);
    FAIL_IF(data == NULL);
    strcpy(data, "overflow");
    FAIL_IF(RingBufferPush(rb, data, 9) != 0);

    FAIL_IF(SC_ATOMIC_GET(rb->dropped) == 0);

    RingBufferDestroy(rb);
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
    UtRegisterTest("KafkaTestRingBufferBasic", KafkaTestRingBufferBasic);
    UtRegisterTest("KafkaTestRingBufferOverflow", KafkaTestRingBufferOverflow);
#endif
}

#else /* !HAVE_LIBRDKAFKA */

void SCEveKafkaInitialize(void)
{
    SCLogNotice("Kafka EVE output support not compiled in (librdkafka not found)");
}

#endif /* HAVE_LIBRDKAFKA */
