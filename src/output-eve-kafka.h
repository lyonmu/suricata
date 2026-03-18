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

/* librdkafka internal queue and performance settings */
#define KAFKA_QUEUE_BUFFERING_MAX_MSGS    100000   /* Max messages in queue */
#define KAFKA_QUEUE_BUFFERING_MAX_KBYTES  1048576  /* Max queue size in KB (1GB) */
#define KAFKA_MESSAGE_TIMEOUT_MS          300000   /* Message timeout (5 min) */
#define KAFKA_SOCKET_TIMEOUT_MS           30000    /* Socket timeout (30 sec) */
#define KAFKA_METADATA_MAX_AGE_MS         300000   /* Metadata refresh interval (5 min) */
#define KAFKA_RETRY_BACKOFF_MS            100      /* Retry backoff interval */
/* Linger.ms is handled by librdkafka internally, no application batching needed */
#define KAFKA_LINGER_MS                   5        /* Producer linger time (librdkafka handles batching) */

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
    int partition;                   /* Topic partition count for auto-creation (-1=1, 0=1, N=N partitions) */
    int ring_buffer_size;            /* Local ring buffer capacity */

    /* librdkafka internal queue settings (batching handled by librdkafka) */
    int queue_buffering_max_messages;
    int queue_buffering_max_kbytes;
    int message_timeout_ms;
    int socket_timeout_ms;
    int metadata_max_age_ms;
    int retry_backoff_ms;
    int linger_ms;                   /* librdkafka internal batching */

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

typedef struct SCEveKafkaRingBufferEntry_ {
    char *data;                      /* JSON message data (owned by ring buffer after push) */
    size_t len;                      /* Data length */
} SCEveKafkaRingBufferEntry;

typedef struct SCEveKafkaRingBuffer_ {
    SCEveKafkaRingBufferEntry *entries;
    uint32_t head;                   /* Write position (producer) */
    uint32_t tail;                   /* Read position (consumer) */
    uint32_t size;                   /* Buffer size (power of 2 recommended) */
    SCSpinlock lock;                 /* Spinlock for thread safety */
    SC_ATOMIC_DECLARE(uint64_t, dropped);  /* Dropped messages count - atomic */
    SC_ATOMIC_DECLARE(uint64_t, pushed);   /* Total messages pushed - atomic */
    SC_ATOMIC_DECLARE(uint64_t, popped);   /* Total messages popped - atomic */
} SCEveKafkaRingBuffer;

#ifdef HAVE_LIBRDKAFKA
#include <librdkafka/rdkafka.h>

typedef struct SCEveKafkaContext_ {
    rd_kafka_t *rk;                  /* Kafka producer handle */
    KafkaSetup setup;                /* Configuration (owned by this struct) */
    SCEveKafkaRingBuffer *ring_buffer;  /* Ring buffer for event queuing */
    pthread_t producer_thread;       /* Background producer thread */
    SC_ATOMIC_DECLARE(int, stop_flag); /* Thread stop signal (set to 1 to stop) */

    /* Statistics - atomic for thread-safe updates */
    SC_ATOMIC_DECLARE(uint64_t, messages_sent);
    SC_ATOMIC_DECLARE(uint64_t, messages_failed);
    SC_ATOMIC_DECLARE(uint64_t, messages_dropped);
    SC_ATOMIC_DECLARE(uint64_t, bytes_sent);
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
