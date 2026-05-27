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
 */

#ifndef SURICATA_OUTPUT_EVE_KAFKA_H
#define SURICATA_OUTPUT_EVE_KAFKA_H

/* Default values for configuration */
#define KAFKA_RING_BUFFER_SIZE_DEFAULT    65536    /* Ring buffer capacity (configurable) */
#define KAFKA_RING_BUFFER_MAX_BYTES       67108864 /* Ring buffer max bytes (64MB) */
#define KAFKA_TOPIC_PARTITIONS_DEFAULT    3
#define KAFKA_MAX_DRAIN_BATCH_DEFAULT     256
#define KAFKA_IDLE_POLL_MS_DEFAULT        10

/* librdkafka internal queue and performance settings */
#define KAFKA_QUEUE_BUFFERING_MAX_MSGS    100000
#define KAFKA_QUEUE_BUFFERING_MAX_KBYTES  131072
#define KAFKA_MESSAGE_TIMEOUT_MS          300000
#define KAFKA_SOCKET_TIMEOUT_MS           30000
#define KAFKA_METADATA_MAX_AGE_MS         300000
#define KAFKA_RETRY_BACKOFF_MS            100
#define KAFKA_RETRY_BACKOFF_MAX_MS        1000
#define KAFKA_RECONNECT_BACKOFF_MS        100
#define KAFKA_RECONNECT_BACKOFF_MAX_MS    10000
#define KAFKA_LINGER_MS                   5

/* Compression types */
typedef enum {
    KAFKA_COMPRESSION_NONE = 0,
    KAFKA_COMPRESSION_GZIP,
    KAFKA_COMPRESSION_SNAPPY,
    KAFKA_COMPRESSION_LZ4,
    KAFKA_COMPRESSION_ZSTD,
} KafkaCompressionType;

/* Security protocols */
typedef enum {
    KAFKA_SECURITY_PLAINTEXT = 0,
    KAFKA_SECURITY_SSL,
    KAFKA_SECURITY_SASL_PLAINTEXT,
    KAFKA_SECURITY_SASL_SSL,
} KafkaSecurityProtocol;

/* Acknowledgment modes */
typedef enum {
    KAFKA_ACKS_ZERO = 0,    /* Fire and forget */
    KAFKA_ACKS_ONE,         /* Leader acknowledgment */
    KAFKA_ACKS_ALL,         /* All replicas acknowledgment */
} KafkaAcksMode;

typedef struct KafkaSetup_ {
    /* Required settings */
    char *brokers;                   /* Comma-separated broker list */
    char *topic;                     /* Target Kafka topic */
    char *client_id;                 /* Client identifier */

    /* Performance settings */
    KafkaCompressionType compression; /* Compression codec */
    KafkaAcksMode acks;              /* Acknowledgment mode */
    bool topic_auto_create;
    int topic_partitions;
    int ring_buffer_size;
    uint64_t ring_buffer_max_bytes;
    int max_drain_batch;
    int idle_poll_ms;

    /* Security settings */
    KafkaSecurityProtocol security_protocol;
    char *ssl_ca_location;
    char *ssl_certificate_location;
    char *ssl_key_location;
    char *ssl_key_password;
    char *sasl_mechanism;
    char *sasl_username;
    char *sasl_password;
} KafkaSetup;

typedef enum KafkaQueuePushResult_ {
    KAFKA_QUEUE_PUSH_OK,
    KAFKA_QUEUE_PUSH_DROPPED,
    KAFKA_QUEUE_PUSH_CLOSED,
} KafkaQueuePushResult;

typedef struct SCEveKafkaQueueEntry_ {
    uint8_t *data;
    size_t len;
} SCEveKafkaQueueEntry;

typedef struct SCEveKafkaQueue_ {
    SCEveKafkaQueueEntry *entries;
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    uint32_t capacity;
    uint64_t current_bytes;
    uint64_t max_bytes;
    bool closing;
    SCSpinlock lock;
    uint64_t dropped;
    uint64_t pushed;
    uint64_t popped;
} SCEveKafkaQueue;

typedef struct SCEveKafkaQueueRegistry_ {
    SCEveKafkaQueue **queues;
    uint32_t queue_count;
    uint32_t queue_capacity;
    uint32_t next_queue;
    SCMutex lock;
} SCEveKafkaQueueRegistry;

typedef struct SCEveKafkaThreadData_ {
    SCEveKafkaQueue *queue;
} SCEveKafkaThreadData;

#ifdef HAVE_LIBRDKAFKA
#include <librdkafka/rdkafka.h>

typedef struct SCEveKafkaContext_ {
    rd_kafka_t *rk;                  /* Kafka producer handle */
    KafkaSetup setup;                /* Configuration (owned by this struct) */
    pthread_t producer_thread;       /* Background producer thread */
    SC_ATOMIC_DECLARE(int, stop_flag); /* Thread stop signal (set to 1 to stop) */
    SCEveKafkaQueueRegistry *registry; /* Registry of per-thread queues */

    /* Statistics - atomic for thread-safe updates */
    SC_ATOMIC_DECLARE(uint64_t, messages_sent);
    SC_ATOMIC_DECLARE(uint64_t, messages_failed);
    SC_ATOMIC_DECLARE(uint64_t, messages_dropped_queue);
    SC_ATOMIC_DECLARE(uint64_t, messages_dropped_produce);
    SC_ATOMIC_DECLARE(uint64_t, bytes_sent);
    SC_ATOMIC_DECLARE(uint64_t, messages_queued);
    SC_ATOMIC_DECLARE(uint64_t, bytes_queued);
    SC_ATOMIC_DECLARE(uint64_t, delivery_callback_count);
} SCEveKafkaContext;

#else /* !HAVE_LIBRDKAFKA */

typedef struct SCEveKafkaContext_ {
    KafkaSetup setup;
    void *dummy;
} SCEveKafkaContext;

#endif /* HAVE_LIBRDKAFKA */

/* Function declarations */
void SCEveKafkaInitialize(void);

#ifdef UNITTESTS
void KafkaRegisterTests(void);
#endif

#endif /* SURICATA_OUTPUT_EVE_KAFKA_H */
