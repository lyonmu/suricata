# Kafka Config Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove fixed Kafka partition configuration and low-frequency librdkafka tuning options from the Kafka EVE user configuration while keeping internal producer defaults and changing auto-created topics to 3 partitions by default.

**Architecture:** Keep the existing Kafka EVE producer thread, per-thread queues, and librdkafka producer configuration flow. Simplify `KafkaSetup` so it stores only user-supported settings, always produce with `RD_KAFKA_PARTITION_UA`, and apply removed librdkafka tuning values from internal constants.

**Tech Stack:** C, Suricata EVE output filetype API, Suricata unit test framework, librdkafka producer API, Autotools build.

---

## Scope Check

The approved spec covers one subsystem: Kafka EVE output configuration and partition behavior. It is small enough for one implementation plan and can be delivered through four focused commits.

## File Structure

- `src/output-eve-kafka.h`: owns Kafka internal default constants and the `KafkaSetup` struct. Remove user-configured partition and low-frequency librdkafka fields from this struct.
- `src/output-eve-kafka.c`: owns config parsing, librdkafka config creation, queue draining, producing, and unit tests. Remove parsing for deleted options, keep internal defaults in `KafkaCreateRdKafkaConf()`, and force automatic partitioning.
- `suricata.yaml.in`: owns the sample Kafka EVE configuration block. Remove deleted options from the sample and document automatic message partitioning.

### Task 1: Remove Deleted Config Parsing And Keep Internal Defaults

**Files:**
- Modify: `src/output-eve-kafka.h`
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c`

- [ ] **Step 1: Update config tests first**

In `src/output-eve-kafka.c`, delete these test functions:

```c
static int KafkaTestParseConfigInvalidPartition(void)
static int KafkaTestParseConfigInvalidReconnectBackoffOrder(void)
static int KafkaTestParseConfigInvalidRetryBackoffOrder(void)
static int KafkaTestParseConfigValidRetryBackoffZero(void)
```

In `KafkaTestParseConfigDefaults()`, keep the existing assertions and add checks that removed fields are no longer part of `KafkaSetup` by not referencing them. The function should remain:

```c
static int KafkaTestParseConfigDefaults(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) != 0);
    FAIL_IF(setup.ring_buffer_max_bytes != KAFKA_RING_BUFFER_MAX_BYTES);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}
```

In `KafkaTestParseConfigHighThroughputDefaults()`, remove the partition assertion and set the topic partition default to 3:

```c
static int KafkaTestParseConfigHighThroughputDefaults(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) != 0);

    FAIL_IF(setup.topic_auto_create != false);
    FAIL_IF(setup.topic_partitions != 3);
    FAIL_IF(setup.max_drain_batch != 256);
    FAIL_IF(setup.idle_poll_ms != 10);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}
```

In `SCEveKafkaInitialize()`, remove these test registrations:

```c
UtRegisterTest("KafkaTestParseConfigInvalidPartition", KafkaTestParseConfigInvalidPartition);
UtRegisterTest("KafkaTestParseConfigInvalidReconnectBackoffOrder",
        KafkaTestParseConfigInvalidReconnectBackoffOrder);
UtRegisterTest("KafkaTestParseConfigInvalidRetryBackoffOrder",
        KafkaTestParseConfigInvalidRetryBackoffOrder);
UtRegisterTest("KafkaTestParseConfigValidRetryBackoffZero",
        KafkaTestParseConfigValidRetryBackoffZero);
```

- [ ] **Step 2: Run focused tests and confirm the compile fails**

Run:

```bash
make -C src suricata
```

Expected: compile fails because `KafkaSetup` still contains fields and code still references tests that were deleted, or because the implementation still asserts the old default.

- [ ] **Step 3: Simplify `KafkaSetup`**

In `src/output-eve-kafka.h`, change the topic partition default and remove the deleted user-configured fields from `KafkaSetup`.

Use this constants section:

```c
#define KAFKA_RING_BUFFER_SIZE_DEFAULT    65536    /* Ring buffer capacity (configurable) */
#define KAFKA_RING_BUFFER_MAX_BYTES       67108864 /* Ring buffer max bytes (64MB) */
#define KAFKA_TOPIC_PARTITIONS_DEFAULT    3
#define KAFKA_MAX_DRAIN_BATCH_DEFAULT     256
#define KAFKA_IDLE_POLL_MS_DEFAULT        10
```

Keep these internal librdkafka constants in the same header:

```c
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
```

In `KafkaSetup`, remove these fields:

```c
int partition;
int queue_buffering_max_messages;
int queue_buffering_max_kbytes;
int message_timeout_ms;
int socket_timeout_ms;
int metadata_max_age_ms;
int retry_backoff_ms;
int retry_backoff_max_ms;
int reconnect_backoff_ms;
int reconnect_backoff_max_ms;
int linger_ms;
```

- [ ] **Step 4: Remove parsing for deleted options**

In `KafkaParseConfig()` in `src/output-eve-kafka.c`, delete these default assignments:

```c
setup->partition = RD_KAFKA_PARTITION_UA;
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
```

Delete the `SCConfGetChildValueInt()` blocks for these YAML names:

```c
"partition"
"queue-buffering-max-messages"
"queue-buffering-max-kbytes"
"message-timeout-ms"
"socket-timeout-ms"
"metadata-max-age-ms"
"retry-backoff-ms"
"retry-backoff-max-ms"
"reconnect-backoff-ms"
"reconnect-backoff-max-ms"
"linger-ms"
```

Delete the complete retry and reconnect ordering checks. Remove the block whose
error message starts with:

```c
SCLogError("Kafka: invalid reconnect backoff configuration: reconnect-backoff-max-ms "
```

Also remove the block whose error message starts with:

```c
SCLogError("Kafka: invalid retry backoff configuration: retry-backoff-max-ms (%d) "
```

- [ ] **Step 5: Apply internal librdkafka defaults from constants**

In `KafkaCreateRdKafkaConf()`, replace references to removed `setup` fields with constants.

Use these exact replacements:

```c
snprintf(buf, sizeof(buf), "%d", KAFKA_LINGER_MS);
snprintf(buf, sizeof(buf), "%d", KAFKA_QUEUE_BUFFERING_MAX_MSGS);
snprintf(buf, sizeof(buf), "%d", KAFKA_QUEUE_BUFFERING_MAX_KBYTES);
snprintf(buf, sizeof(buf), "%d", KAFKA_RETRY_BACKOFF_MS);
snprintf(buf, sizeof(buf), "%d", KAFKA_RETRY_BACKOFF_MAX_MS);
snprintf(buf, sizeof(buf), "%d", KAFKA_RECONNECT_BACKOFF_MS);
snprintf(buf, sizeof(buf), "%d", KAFKA_RECONNECT_BACKOFF_MAX_MS);
snprintf(buf, sizeof(buf), "%d", KAFKA_MESSAGE_TIMEOUT_MS);
snprintf(buf, sizeof(buf), "%d", KAFKA_SOCKET_TIMEOUT_MS);
snprintf(buf, sizeof(buf), "%d", KAFKA_METADATA_MAX_AGE_MS);
```

In the Kafka initialization notice, remove queue buffering and linger values. Use:

```c
SCLogNotice("Kafka producer initialized (brokers: %s, topic: %s, ring_buffer_size: %d, "
            "ring_buffer_max_bytes: %" PRIu64 ")",
        ctx->setup.brokers, ctx->setup.topic, ctx->setup.ring_buffer_size,
        ctx->setup.ring_buffer_max_bytes);
```

- [ ] **Step 6: Run focused config tests**

Run:

```bash
make -C src suricata
./src/suricata -u -U KafkaTestParseConfigDefaults
./src/suricata -u -U KafkaTestParseConfigHighThroughputDefaults
./src/suricata -u -U KafkaTestParseConfigTopicAutoCreateEnabled
./src/suricata -u -U KafkaTestParseConfigInvalidTopicPartitions
```

Expected: all commands pass.

- [ ] **Step 7: Commit config simplification**

Run:

```bash
git add src/output-eve-kafka.h src/output-eve-kafka.c
git commit -m "output/eve-kafka: simplify producer config parsing"
```

### Task 2: Force Automatic Kafka Partitioning In Produce Path

**Files:**
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c`

- [ ] **Step 1: Replace configured-partition test**

Delete `KafkaTestDrainUsesConfiguredPartition()`.

Add this test in its place:

```c
static int KafkaTestDrainUsesAutomaticPartition(void)
{
    SCEveKafkaQueueRegistry *registry = KafkaQueueRegistryCreate();
    FAIL_IF_NULL(registry);

    SCEveKafkaQueue *q0 = KafkaQueueCreate(4, 1024);
    FAIL_IF_NULL(q0);
    FAIL_IF(KafkaQueueRegistryRegister(registry, q0) != 0);

    uint8_t data0[] = "msg";
    FAIL_IF(KafkaQueuePush(q0, data0, sizeof(data0), NULL) != KAFKA_QUEUE_PUSH_OK);

    KafkaTestDrainCtx dctx = { 0 };
    uint32_t drained = KafkaDrainQueuesInternal(registry, 8, 10, "test-topic",
            KafkaTestDrainProduceHook, &dctx, KafkaTestDrainPollHook, &dctx);

    FAIL_IF(drained != 1);
    FAIL_IF(dctx.produced_count != 1);
    FAIL_IF(dctx.partitions[0] != RD_KAFKA_PARTITION_UA);

    SCFree(dctx.produced[0]);
    KafkaQueueRegistryDestroy(registry);
    PASS;
}
```

In `SCEveKafkaInitialize()`, replace the old registration:

```c
UtRegisterTest("KafkaTestDrainUsesConfiguredPartition", KafkaTestDrainUsesConfiguredPartition);
```

with:

```c
UtRegisterTest("KafkaTestDrainUsesAutomaticPartition", KafkaTestDrainUsesAutomaticPartition);
```

- [ ] **Step 2: Run the new test and confirm it fails to compile**

Run:

```bash
make -C src suricata
```

Expected: compile fails because `KafkaDrainQueuesInternal()` still requires a partition argument.

- [ ] **Step 3: Remove partition from drain helper signatures**

In the forward declarations near the top of `src/output-eve-kafka.c`, change:

```c
static uint32_t KafkaDrainQueuesInternal(SCEveKafkaQueueRegistry *registry,
        uint32_t max_batch, int idle_poll_ms, const char *topic, int32_t partition,
        KafkaDrainProduceHookFunc produce_hook, void *produce_ctx,
        KafkaDrainPollHookFunc poll_hook, void *poll_ctx);
```

to:

```c
static uint32_t KafkaDrainQueuesInternal(SCEveKafkaQueueRegistry *registry,
        uint32_t max_batch, int idle_poll_ms, const char *topic,
        KafkaDrainProduceHookFunc produce_hook, void *produce_ctx,
        KafkaDrainPollHookFunc poll_hook, void *poll_ctx);
```

Change the function definition the same way. Inside the function, replace:

```c
rd_kafka_resp_err_t err = produce_hook(produce_ctx, topic,
        partition, entry->data, entry->len, NULL, 0);
```

with:

```c
rd_kafka_resp_err_t err = produce_hook(produce_ctx, topic,
        RD_KAFKA_PARTITION_UA, entry->data, entry->len, NULL, 0);
```

- [ ] **Step 4: Update all drain helper call sites**

In `KafkaProducerThread()`, change both calls from:

```c
KafkaDrainQueuesInternal(ctx->registry,
        ctx->setup.max_drain_batch, ctx->setup.idle_poll_ms, ctx->setup.topic,
        ctx->setup.partition,
        KafkaDrainProduceHook, ctx, KafkaDrainPollHook, ctx);
```

to:

```c
KafkaDrainQueuesInternal(ctx->registry,
        ctx->setup.max_drain_batch, ctx->setup.idle_poll_ms, ctx->setup.topic,
        KafkaDrainProduceHook, ctx, KafkaDrainPollHook, ctx);
```

Update unit test calls that still pass `RD_KAFKA_PARTITION_UA` or a numeric partition by removing that argument. For example:

```c
uint32_t drained = KafkaDrainQueuesInternal(registry, 8, 17, "test-topic",
        KafkaTestDrainProduceHook, &dctx, KafkaTestDrainPollHook, &dctx);
```

- [ ] **Step 5: Keep the actual librdkafka call automatic**

In `KafkaDrainProduceHook()`, leave the signature accepting `int32_t partition` so the test hook can observe the effective partition. Add this assertion-style guard before the produce loop:

```c
if (partition != RD_KAFKA_PARTITION_UA) {
    SCLogWarning("Kafka: ignoring non-automatic partition value %d", partition);
    partition = RD_KAFKA_PARTITION_UA;
}
```

The `rd_kafka_producev()` call should continue to pass:

```c
RD_KAFKA_V_PARTITION(partition)
```

Because the only production caller now passes `RD_KAFKA_PARTITION_UA`, this prevents fixed partition output while keeping the test seam small.

- [ ] **Step 6: Run focused drain tests**

Run:

```bash
make -C src suricata
./src/suricata -u -U KafkaTestDrainRoundRobinFairness
./src/suricata -u -U KafkaTestDrainIdlePollsWithTimeout
./src/suricata -u -U KafkaTestDrainUsesAutomaticPartition
```

Expected: all commands pass.

- [ ] **Step 7: Commit automatic partitioning**

Run:

```bash
git add src/output-eve-kafka.c
git commit -m "output/eve-kafka: always use automatic partitioning"
```

### Task 3: Simplify Kafka Example Configuration

**Files:**
- Modify: `suricata.yaml.in`

- [ ] **Step 1: Edit the Kafka example block**

In `suricata.yaml.in`, replace the Kafka topic and performance settings block with:

```yaml
      #  # Topic settings
      #  topic-auto-create: no            # Enable automatic topic creation (default: no)
      #  topic-partitions: 3              # Partitions for auto-created topics (default: 3)
      #
      #  # Performance settings
      #  compression: none                # none|gzip|snappy|lz4|zstd (default: none)
      #  acks: 1                          # 0|1|all (default: 1)
      #                                   #   0 = fire and forget (fastest, no durability)
      #                                   #   1 = leader ack (balanced)
      #                                   #   all = all replicas (slowest, most durable)
      #                                   # Message partitioning is automatic.
      #  ring-buffer-size: 65536          # Max messages in per-thread queue (default: 65536)
      #  ring-buffer-max-bytes: 67108864  # Max bytes in per-thread queue (default: 64MB)
      #  max-drain-batch: 256             # Max messages drained per poll cycle (default: 256)
      #  idle-poll-ms: 10                 # Poll timeout when no messages to drain (default: 10)
      #
```

Delete the old commented `partition` line and the whole commented `librdkafka internal queue settings` block.

- [ ] **Step 2: Verify removed YAML keys are gone**

Run:

```bash
rg -n "partition:|queue-buffering|max-drain|idle-poll|message-timeout|socket-timeout|metadata-max-age|retry-backoff|reconnect-backoff|linger-ms" suricata.yaml.in
```

Expected: output still contains `topic-partitions`, `max-drain-batch`, and `idle-poll-ms`, but does not contain `partition:`, `queue-buffering`, `message-timeout`, `socket-timeout`, `metadata-max-age`, `retry-backoff`, `reconnect-backoff`, or `linger-ms`.

- [ ] **Step 3: Commit YAML simplification**

Run:

```bash
git add suricata.yaml.in
git commit -m "output/eve-kafka: simplify sample configuration"
```

### Task 4: Full Verification And Formatting

**Files:**
- Modify only if formatting changes: `src/output-eve-kafka.c`
- Modify only if formatting changes: `src/output-eve-kafka.h`

- [ ] **Step 1: Format touched C files**

Run:

```bash
scripts/clang-format.sh check-branch --diffstat
```

Expected: command exits 0, or reports only formatting differences in touched C files.

If formatting differences are reported for touched files, run:

```bash
clang-format -i src/output-eve-kafka.c src/output-eve-kafka.h
```

Then rerun:

```bash
scripts/clang-format.sh check-branch --diffstat
```

Expected: exits 0.

- [ ] **Step 2: Run the Kafka-focused unit tests**

Run:

```bash
make -C src suricata
./src/suricata -u -U KafkaTestParseConfigDefaults
./src/suricata -u -U KafkaTestParseConfigHighThroughputDefaults
./src/suricata -u -U KafkaTestParseConfigTopicAutoCreateEnabled
./src/suricata -u -U KafkaTestParseConfigInvalidTopicPartitions
./src/suricata -u -U KafkaTestDrainRoundRobinFairness
./src/suricata -u -U KafkaTestDrainIdlePollsWithTimeout
./src/suricata -u -U KafkaTestDrainUsesAutomaticPartition
./src/suricata -u -U KafkaTestTopicCreateAutoCreateEnabled
```

Expected: all unit tests pass.

- [ ] **Step 3: Run broader verification when the tree is configured**

If `Makefile` exists at repository root, run:

```bash
make check
```

Expected: exits 0.

If the tree is not configured, run the user's build path:

```bash
./autogen.sh
./configure --enable-geoip --enable-ebpf --enable-hiredis --enable-ja4 --enable-ja3 --enable-kafka
make -j "$(nproc)"
```

Expected: build exits 0.

- [ ] **Step 4: Verify deleted symbols and config keys**

Run:

```bash
rg -n "setup->partition|KafkaTestParseConfigInvalidPartition|KafkaTestDrainUsesConfiguredPartition|queue_buffering_max_messages|queue_buffering_max_kbytes|message_timeout_ms|socket_timeout_ms|metadata_max_age_ms|retry_backoff_ms|retry_backoff_max_ms|reconnect_backoff_ms|reconnect_backoff_max_ms|linger_ms" src/output-eve-kafka.c src/output-eve-kafka.h
```

Expected: no output.

Run:

```bash
rg -n "partition:|queue-buffering|message-timeout|socket-timeout|metadata-max-age|retry-backoff|reconnect-backoff|linger-ms" suricata.yaml.in
```

Expected: no output for deleted keys. `topic-partitions` is allowed and should remain.

- [ ] **Step 5: Commit verification fixes**

If formatting or verification changed files, run:

```bash
git add src/output-eve-kafka.c src/output-eve-kafka.h suricata.yaml.in
git commit -m "output/eve-kafka: finish config simplification"
```

If no files changed, do not create an empty commit.
