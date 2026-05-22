# Kafka High-Throughput Queue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Kafka EVE output shared ring buffer with per-EVE-thread bounded queues, non-blocking producer polling, explicit topic auto-create configuration, and accurate drop statistics.

**Architecture:** Keep one librdkafka producer and one background producer thread, but register one bounded queue per EVE output thread. `KafkaWrite()` writes only to its thread queue, while the producer thread drains registered queues in round-robin batches and uses a zero-timeout `rd_kafka_poll()` call after active work or `idle-poll-ms` while idle.

**Tech Stack:** C, Suricata EVE output filetype API, Suricata unit test framework, Suricata atomics/locks, librdkafka producer API, Autotools build.

---

## Scope Check

The spec is one subsystem: Kafka EVE output throughput and startup behavior. It can be implemented in one plan with task-level commits because every task leaves the Kafka output buildable and testable.

## File Structure

- `src/output-eve-kafka.h`: owns Kafka defaults, `KafkaSetup`, queue/registry forward declarations, and Kafka context statistics fields.
- `src/output-eve-kafka.c`: owns queue primitives, registry lifecycle, config parsing, librdkafka config, producer loop, write path, shutdown, and unit tests.
- `suricata.yaml.in`: documents Kafka output operational options and migration notes.

### Task 1: Add Configuration Fields, Defaults, And Bounded Numeric Parsing

**Files:**
- Modify: `src/output-eve-kafka.h`
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c` unit test section

- [ ] **Step 1: Write failing config tests**

Add these tests near the existing Kafka parse config tests:

```c
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
```

Register them in `KafkaRegisterTests()`:

```c
UtRegisterTest("KafkaTestParseConfigHighThroughputDefaults",
        KafkaTestParseConfigHighThroughputDefaults);
UtRegisterTest("KafkaTestParseConfigTopicAutoCreateEnabled",
        KafkaTestParseConfigTopicAutoCreateEnabled);
UtRegisterTest("KafkaTestParseConfigInvalidIntOverflow",
        KafkaTestParseConfigInvalidIntOverflow);
UtRegisterTest("KafkaTestParseConfigInvalidTopicPartitions",
        KafkaTestParseConfigInvalidTopicPartitions);
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `./src/suricata -u -U KafkaTestParseConfigHighThroughputDefaults`

Expected: FAIL because `topic_auto_create`, `topic_partitions`, `max_drain_batch`, and `idle_poll_ms` do not exist yet.

- [ ] **Step 3: Extend defaults and `KafkaSetup`**

In `src/output-eve-kafka.h`, replace the current partition comment and add defaults:

```c
#define KAFKA_TOPIC_PARTITIONS_DEFAULT 1
#define KAFKA_MAX_DRAIN_BATCH_DEFAULT 256
#define KAFKA_IDLE_POLL_MS_DEFAULT    10

typedef struct KafkaSetup_ {
    char *brokers;
    char *topic;
    char *client_id;

    KafkaCompressionType compression;
    KafkaAcksMode acks;
    int partition;
    bool topic_auto_create;
    int topic_partitions;
    int ring_buffer_size;
    uint64_t ring_buffer_max_bytes;
    int max_drain_batch;
    int idle_poll_ms;
```

Keep the remaining existing librdkafka and security fields after these fields.

- [ ] **Step 4: Replace numeric validation helpers**

In `src/output-eve-kafka.c`, replace `KafkaValidateInt()` and `KafkaValidateIntGreaterThanZero()` with:

```c
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
```

Add `#include <limits.h>` with the existing includes if it is not already available through included headers.

- [ ] **Step 5: Parse new options**

In `KafkaParseConfig()`, set defaults before parsing optional overrides:

```c
setup->partition = RD_KAFKA_PARTITION_UA;
setup->topic_auto_create = false;
setup->topic_partitions = KAFKA_TOPIC_PARTITIONS_DEFAULT;
setup->ring_buffer_size = KAFKA_RING_BUFFER_SIZE_DEFAULT;
setup->ring_buffer_max_bytes = KAFKA_RING_BUFFER_MAX_BYTES;
setup->max_drain_batch = KAFKA_MAX_DRAIN_BATCH_DEFAULT;
setup->idle_poll_ms = KAFKA_IDLE_POLL_MS_DEFAULT;
```

Parse the new options with bounded casts:

```c
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
```

Use `KafkaValidateIntTarget()` for every existing `int` field before casting.

- [ ] **Step 6: Run and commit**

Run: `./src/suricata -u -U KafkaTestParseConfig`

Expected: PASS for all Kafka parse config tests.

```bash
git add src/output-eve-kafka.h src/output-eve-kafka.c
git commit -m "output/eve-kafka: add high throughput queue config"
```

### Task 2: Replace Shared Ring Buffer With Closable Per-Thread Queue Primitive

**Files:**
- Modify: `src/output-eve-kafka.h`
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c` unit test section

- [ ] **Step 1: Write failing queue primitive tests**

Add tests near the current ring buffer tests:

```c
static int KafkaTestQueueBasicPushPop(void)
{
    SCEveKafkaQueue *q = KafkaQueueCreate(4, 64);
    FAIL_IF_NULL(q);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("one"), 3) != KAFKA_QUEUE_PUSH_OK);

    SCEveKafkaQueueEntry entry = { 0 };
    FAIL_IF(KafkaQueuePop(q, &entry) != 0);
    FAIL_IF(entry.len != 3);
    FAIL_IF(strcmp(entry.data, "one") != 0);
    SCFree(entry.data);

    KafkaQueueDestroy(q);
    PASS;
}

static int KafkaTestQueueCountBudgetDropOldest(void)
{
    SCEveKafkaQueue *q = KafkaQueueCreate(2, 64);
    FAIL_IF_NULL(q);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("one"), 3) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("two"), 3) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("three"), 5) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(SC_ATOMIC_GET(q->dropped) != 1);

    SCEveKafkaQueueEntry entry = { 0 };
    FAIL_IF(KafkaQueuePop(q, &entry) != 0);
    FAIL_IF(strcmp(entry.data, "two") != 0);
    SCFree(entry.data);

    KafkaQueueDestroy(q);
    PASS;
}

static int KafkaTestQueueByteBudgetDropOldest(void)
{
    SCEveKafkaQueue *q = KafkaQueueCreate(8, 8);
    FAIL_IF_NULL(q);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("aaaa"), 4) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("bbbb"), 4) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("cccc"), 4) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(SC_ATOMIC_GET(q->dropped) != 1);
    FAIL_IF(q->current_bytes != 8);

    KafkaQueueDestroy(q);
    PASS;
}

static int KafkaTestQueueOversizedDrop(void)
{
    SCEveKafkaQueue *q = KafkaQueueCreate(8, 4);
    FAIL_IF_NULL(q);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("12345"), 5) != KAFKA_QUEUE_PUSH_DROPPED);
    FAIL_IF(SC_ATOMIC_GET(q->dropped) != 1);

    KafkaQueueDestroy(q);
    PASS;
}

static int KafkaTestQueueClosedRejectsWrites(void)
{
    SCEveKafkaQueue *q = KafkaQueueCreate(8, 64);
    FAIL_IF_NULL(q);
    KafkaQueueClose(q);
    FAIL_IF(KafkaQueuePush(q, SCStrdup("closed"), 6) != KAFKA_QUEUE_PUSH_CLOSED);
    FAIL_IF(SC_ATOMIC_GET(q->dropped) != 1);

    KafkaQueueDestroy(q);
    PASS;
}
```

Register:

```c
UtRegisterTest("KafkaTestQueueBasicPushPop", KafkaTestQueueBasicPushPop);
UtRegisterTest("KafkaTestQueueCountBudgetDropOldest", KafkaTestQueueCountBudgetDropOldest);
UtRegisterTest("KafkaTestQueueByteBudgetDropOldest", KafkaTestQueueByteBudgetDropOldest);
UtRegisterTest("KafkaTestQueueOversizedDrop", KafkaTestQueueOversizedDrop);
UtRegisterTest("KafkaTestQueueClosedRejectsWrites", KafkaTestQueueClosedRejectsWrites);
```

- [ ] **Step 2: Run tests to verify failure**

Run: `./src/suricata -u -U KafkaTestQueue`

Expected: FAIL because `SCEveKafkaQueue` and queue functions are not defined yet.

- [ ] **Step 3: Replace ring buffer types**

In `src/output-eve-kafka.h`, replace `SCEveKafkaRingBufferEntry` and `SCEveKafkaRingBuffer` with:

```c
typedef enum KafkaQueuePushResult_ {
    KAFKA_QUEUE_PUSH_OK = 0,
    KAFKA_QUEUE_PUSH_DROPPED,
    KAFKA_QUEUE_PUSH_CLOSED,
} KafkaQueuePushResult;

typedef struct SCEveKafkaQueueEntry_ {
    char *data;
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
    SC_ATOMIC_DECLARE(uint64_t, dropped);
    SC_ATOMIC_DECLARE(uint64_t, pushed);
    SC_ATOMIC_DECLARE(uint64_t, popped);
} SCEveKafkaQueue;
```

- [ ] **Step 4: Implement queue helpers**

In `src/output-eve-kafka.c`, replace `RingBufferInit()`, `RingBufferPush()`, `RingBufferPop()`, and `RingBufferDestroy()` with:

```c
static void KafkaQueueDropOldestLocked(SCEveKafkaQueue *q)
{
    SCEveKafkaQueueEntry *old = &q->entries[q->tail];
    if (old->data != NULL) {
        DEBUG_VALIDATE_BUG_ON(q->current_bytes < old->len);
        q->current_bytes -= old->len;
        SCFree(old->data);
        old->data = NULL;
        old->len = 0;
        SC_ATOMIC_ADD(q->dropped, 1);
    }
    q->tail = (q->tail + 1) % q->capacity;
    q->count--;
}

static SCEveKafkaQueue *KafkaQueueCreate(uint32_t capacity, uint64_t max_bytes)
{
    if (capacity < 2 || max_bytes == 0) {
        SCLogError("Kafka queue capacity must be >= 2 and max bytes must be > 0");
        return NULL;
    }

    SCEveKafkaQueue *q = SCCalloc(1, sizeof(*q));
    if (q == NULL) {
        return NULL;
    }
    q->entries = SCCalloc(capacity, sizeof(*q->entries));
    if (q->entries == NULL) {
        SCFree(q);
        return NULL;
    }

    q->capacity = capacity;
    q->max_bytes = max_bytes;
    SC_ATOMIC_INIT(q->dropped);
    SC_ATOMIC_INIT(q->pushed);
    SC_ATOMIC_INIT(q->popped);
    SCSpinInit(&q->lock, 0);
    return q;
}

static KafkaQueuePushResult KafkaQueuePush(SCEveKafkaQueue *q, char *data, size_t len)
{
    DEBUG_VALIDATE_BUG_ON(q == NULL);
    DEBUG_VALIDATE_BUG_ON(data == NULL);

    SCSpinLock(&q->lock);

    if (q->closing) {
        SC_ATOMIC_ADD(q->dropped, 1);
        SCSpinUnlock(&q->lock);
        SCFree(data);
        return KAFKA_QUEUE_PUSH_CLOSED;
    }
    if ((uint64_t)len > q->max_bytes) {
        SC_ATOMIC_ADD(q->dropped, 1);
        SCSpinUnlock(&q->lock);
        SCFree(data);
        return KAFKA_QUEUE_PUSH_DROPPED;
    }

    while (q->count == q->capacity) {
        KafkaQueueDropOldestLocked(q);
    }
    while (q->count > 0 && q->current_bytes + len > q->max_bytes) {
        KafkaQueueDropOldestLocked(q);
    }

    SCEveKafkaQueueEntry *entry = &q->entries[q->head];
    entry->data = data;
    entry->len = len;
    q->current_bytes += len;
    q->head = (q->head + 1) % q->capacity;
    q->count++;
    SC_ATOMIC_ADD(q->pushed, 1);

    SCSpinUnlock(&q->lock);
    return KAFKA_QUEUE_PUSH_OK;
}

static int KafkaQueuePop(SCEveKafkaQueue *q, SCEveKafkaQueueEntry *entry)
{
    DEBUG_VALIDATE_BUG_ON(q == NULL);
    DEBUG_VALIDATE_BUG_ON(entry == NULL);

    int ret = -1;
    SCSpinLock(&q->lock);
    if (q->count > 0) {
        *entry = q->entries[q->tail];
        q->entries[q->tail].data = NULL;
        q->entries[q->tail].len = 0;
        DEBUG_VALIDATE_BUG_ON(q->current_bytes < entry->len);
        q->current_bytes -= entry->len;
        q->tail = (q->tail + 1) % q->capacity;
        q->count--;
        SC_ATOMIC_ADD(q->popped, 1);
        ret = 0;
    }
    SCSpinUnlock(&q->lock);
    return ret;
}

static void KafkaQueueClose(SCEveKafkaQueue *q)
{
    if (q == NULL) {
        return;
    }
    SCSpinLock(&q->lock);
    q->closing = true;
    SCSpinUnlock(&q->lock);
}

static void KafkaQueueDestroy(SCEveKafkaQueue *q)
{
    if (q == NULL) {
        return;
    }
    for (uint32_t i = 0; i < q->capacity; i++) {
        if (q->entries[i].data != NULL) {
            SCFree(q->entries[i].data);
        }
    }
    SCFree(q->entries);
    SCSpinDestroy(&q->lock);
    SCFree(q);
}
```

- [ ] **Step 5: Run and commit**

Run: `./src/suricata -u -U KafkaTestQueue`

Expected: PASS for all queue primitive tests.

```bash
git add src/output-eve-kafka.h src/output-eve-kafka.c
git commit -m "output/eve-kafka: add per-thread queue primitive"
```

### Task 3: Add Queue Registry And Thread-Specific Write Path

**Files:**
- Modify: `src/output-eve-kafka.h`
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c` unit test section

- [ ] **Step 1: Write failing registry tests**

```c
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

    SCEveKafkaQueueEntry entry = { 0 };
    FAIL_IF(KafkaQueuePop(q, &entry) != 0);
    FAIL_IF(entry.len != 22);
    SCFree(entry.data);
    KafkaQueueDestroy(q);
    PASS;
}
```

Register:

```c
UtRegisterTest("KafkaTestQueueRegistryRegistersMultipleQueues",
        KafkaTestQueueRegistryRegistersMultipleQueues);
UtRegisterTest("KafkaTestKafkaWriteUsesThreadQueue", KafkaTestKafkaWriteUsesThreadQueue);
```

- [ ] **Step 2: Run tests to verify failure**

Run: `./src/suricata -u -U KafkaTestQueueRegistry`

Expected: FAIL because the registry and thread data types do not exist yet.

- [ ] **Step 3: Add registry and thread-data types**

In `src/output-eve-kafka.h`, add before `SCEveKafkaContext`:

```c
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
```

Update `SCEveKafkaContext`:

```c
SCEveKafkaQueueRegistry *registry;
pthread_t producer_thread;
SC_ATOMIC_DECLARE(int, stop_flag);
SC_ATOMIC_DECLARE(uint64_t, messages_queued);
SC_ATOMIC_DECLARE(uint64_t, messages_sent);
SC_ATOMIC_DECLARE(uint64_t, messages_failed);
SC_ATOMIC_DECLARE(uint64_t, messages_dropped_queue);
SC_ATOMIC_DECLARE(uint64_t, messages_dropped_produce);
SC_ATOMIC_DECLARE(uint64_t, bytes_queued);
SC_ATOMIC_DECLARE(uint64_t, bytes_sent);
SC_ATOMIC_DECLARE(uint64_t, delivery_callback_count);
```

- [ ] **Step 4: Implement registry helpers**

Add after queue helpers:

```c
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
```

- [ ] **Step 5: Wire `KafkaThreadInit()`, `KafkaThreadDeinit()`, and `KafkaWrite()`**

Replace thread lifecycle:

```c
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

static void KafkaThreadDeinit(const void *init_data, void *thread_data)
{
    SCEveKafkaThreadData *td = (SCEveKafkaThreadData *)thread_data;
    if (td == NULL) {
        return;
    }
    KafkaQueueClose(td->queue);
    SCFree(td);
}
```

Replace `KafkaWrite()` body after argument validation:

```c
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

KafkaQueuePushResult ret = KafkaQueuePush(td->queue, data, (size_t)buffer_len);
if (ret == KAFKA_QUEUE_PUSH_OK) {
    SC_ATOMIC_ADD(ctx->messages_queued, 1);
    SC_ATOMIC_ADD(ctx->bytes_queued, (uint64_t)buffer_len);
} else {
    SC_ATOMIC_ADD(ctx->messages_dropped_queue, 1);
}
return 0;
```

- [ ] **Step 6: Run and commit**

Run: `./src/suricata -u -U KafkaTestKafkaWriteUsesThreadQueue`

Expected: PASS.

```bash
git add src/output-eve-kafka.h src/output-eve-kafka.c
git commit -m "output/eve-kafka: use per-thread queues in write path"
```

### Task 4: Add Round-Robin Drain Helper And Non-Blocking Producer Polling

**Files:**
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c` unit test section

- [ ] **Step 1: Write failing producer drain tests**

Add hook types and tests in the unit test section:

```c
typedef struct KafkaTestDrainCtx_ {
    const char *produced[8];
    int produced_count;
    int poll_timeouts[8];
    int poll_count;
} KafkaTestDrainCtx;

static int KafkaTestDrainProduceHook(void *hook_ctx, char *data, size_t len, bool final_drain)
{
    KafkaTestDrainCtx *tctx = (KafkaTestDrainCtx *)hook_ctx;
    tctx->produced[tctx->produced_count++] = data;
    SCFree(data);
    return 0;
}

static void KafkaTestDrainPollHook(void *hook_ctx, int timeout_ms)
{
    KafkaTestDrainCtx *tctx = (KafkaTestDrainCtx *)hook_ctx;
    tctx->poll_timeouts[tctx->poll_count++] = timeout_ms;
}

static int KafkaTestDrainRoundRobinFairness(void)
{
    SCEveKafkaQueueRegistry *registry = KafkaQueueRegistryCreate();
    FAIL_IF_NULL(registry);
    SCEveKafkaQueue *q0 = KafkaQueueCreate(8, 128);
    SCEveKafkaQueue *q1 = KafkaQueueCreate(8, 128);
    FAIL_IF_NULL(q0);
    FAIL_IF_NULL(q1);
    FAIL_IF(KafkaQueueRegistryRegister(registry, q0) != 0);
    FAIL_IF(KafkaQueueRegistryRegister(registry, q1) != 0);

    FAIL_IF(KafkaQueuePush(q0, SCStrdup("q0-a"), 4) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(q0, SCStrdup("q0-b"), 4) != KAFKA_QUEUE_PUSH_OK);
    FAIL_IF(KafkaQueuePush(q1, SCStrdup("q1-a"), 4) != KAFKA_QUEUE_PUSH_OK);

    KafkaTestDrainCtx tctx = { 0 };
    uint32_t drained = KafkaDrainQueuesInternal(
            registry, 1, false, KafkaTestDrainProduceHook, KafkaTestDrainPollHook, &tctx, 10);

    FAIL_IF(drained != 2);
    FAIL_IF(tctx.produced_count != 2);
    FAIL_IF(strcmp(tctx.produced[0], "q0-a") != 0);
    FAIL_IF(strcmp(tctx.produced[1], "q1-a") != 0);
    FAIL_IF(tctx.poll_count != 1);
    FAIL_IF(tctx.poll_timeouts[0] != 0);

    KafkaQueueRegistryDestroy(registry);
    PASS;
}

static int KafkaTestDrainIdlePollsWithTimeout(void)
{
    SCEveKafkaQueueRegistry *registry = KafkaQueueRegistryCreate();
    FAIL_IF_NULL(registry);
    SCEveKafkaQueue *q0 = KafkaQueueCreate(8, 128);
    FAIL_IF_NULL(q0);
    FAIL_IF(KafkaQueueRegistryRegister(registry, q0) != 0);

    KafkaTestDrainCtx tctx = { 0 };
    uint32_t drained = KafkaDrainQueuesInternal(
            registry, 4, false, KafkaTestDrainProduceHook, KafkaTestDrainPollHook, &tctx, 17);

    FAIL_IF(drained != 0);
    FAIL_IF(tctx.poll_count != 1);
    FAIL_IF(tctx.poll_timeouts[0] != 17);

    KafkaQueueRegistryDestroy(registry);
    PASS;
}
```

Register:

```c
UtRegisterTest("KafkaTestDrainRoundRobinFairness", KafkaTestDrainRoundRobinFairness);
UtRegisterTest("KafkaTestDrainIdlePollsWithTimeout", KafkaTestDrainIdlePollsWithTimeout);
```

- [ ] **Step 2: Run tests to verify failure**

Run: `./src/suricata -u -U KafkaTestDrain`

Expected: FAIL because `KafkaDrainQueuesInternal()` does not exist yet.

- [ ] **Step 3: Add drain hooks and helper**

Add near producer helper declarations:

```c
typedef int (*KafkaDrainProduceHookFunc)(void *hook_ctx, char *data, size_t len, bool final_drain);
typedef void (*KafkaDrainPollHookFunc)(void *hook_ctx, int timeout_ms);
```

Add implementation before `KafkaProducerThread()`:

```c
static int KafkaDrainProduceHook(void *hook_ctx, char *data, size_t len, bool final_drain)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)hook_ctx;
    return KafkaProduceWithRetry(ctx, data, len, final_drain);
}

static void KafkaDrainPollHook(void *hook_ctx, int timeout_ms)
{
    SCEveKafkaContext *ctx = (SCEveKafkaContext *)hook_ctx;
    rd_kafka_poll(ctx->rk, timeout_ms);
}

static uint32_t KafkaDrainQueuesInternal(SCEveKafkaQueueRegistry *registry, uint32_t max_batch,
        bool final_drain, KafkaDrainProduceHookFunc produce_hook, KafkaDrainPollHookFunc poll_hook,
        void *hook_ctx, int idle_poll_ms)
{
    uint32_t drained = 0;

    SCMutexLock(&registry->lock);
    const uint32_t count = registry->queue_count;
    const uint32_t start = registry->next_queue;
    SCMutexUnlock(&registry->lock);

    for (uint32_t offset = 0; offset < count; offset++) {
        const uint32_t index = (start + offset) % count;

        SCMutexLock(&registry->lock);
        SCEveKafkaQueue *queue = registry->queues[index];
        SCMutexUnlock(&registry->lock);

        for (uint32_t batch = 0; batch < max_batch; batch++) {
            SCEveKafkaQueueEntry entry = { 0 };
            if (KafkaQueuePop(queue, &entry) != 0) {
                break;
            }
            produce_hook(hook_ctx, entry.data, entry.len, final_drain);
            drained++;
        }
    }

    SCMutexLock(&registry->lock);
    if (count > 0) {
        registry->next_queue = (start + 1) % count;
    }
    SCMutexUnlock(&registry->lock);

    poll_hook(hook_ctx, drained > 0 ? 0 : idle_poll_ms);
    return drained;
}
```

- [ ] **Step 4: Replace producer loop**

Replace `KafkaProducerThread()` loop and final drain with:

```c
while (SC_ATOMIC_GET(ctx->stop_flag) == 0) {
    KafkaDrainQueuesInternal(ctx->registry, (uint32_t)ctx->setup.max_drain_batch, false,
            KafkaDrainProduceHook, KafkaDrainPollHook, ctx, ctx->setup.idle_poll_ms);
}

SCLogInfo("Kafka producer thread: draining remaining messages");
while (KafkaDrainQueuesInternal(ctx->registry, (uint32_t)ctx->setup.max_drain_batch, true,
               KafkaDrainProduceHook, KafkaDrainPollHook, ctx, 0) > 0) {
}

SCLogInfo("Kafka producer thread: flushing librdkafka queue");
rd_kafka_resp_err_t flush_ret = rd_kafka_flush(ctx->rk, 10000);
if (flush_ret != RD_KAFKA_RESP_ERR_NO_ERROR) {
    SCLogWarning("Kafka producer thread: flush timed out or failed: %s, queue length: %d",
            rd_kafka_err2str(flush_ret), rd_kafka_outq_len(ctx->rk));
}
```

- [ ] **Step 5: Run and commit**

Run: `./src/suricata -u -U KafkaTestDrain`

Expected: PASS.

```bash
git add src/output-eve-kafka.c
git commit -m "output/eve-kafka: drain queues without blocking poll"
```

### Task 5: Update Startup, Topic Auto-Create, Shutdown, And Drop Statistics

**Files:**
- Modify: `src/output-eve-kafka.h`
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c` unit test section

- [ ] **Step 1: Write failing topic and stats tests**

```c
typedef struct KafkaTestTopicCreateCtx_ {
    int calls;
    int partitions;
    int ret;
} KafkaTestTopicCreateCtx;

static int KafkaTestCreateTopicHook(void *hook_ctx, rd_kafka_t *rk,
        const char *topic_name, int num_partitions, int timeout_ms)
{
    KafkaTestTopicCreateCtx *tctx = (KafkaTestTopicCreateCtx *)hook_ctx;
    tctx->calls++;
    tctx->partitions = num_partitions;
    return tctx->ret;
}

static int KafkaTestTopicCreateDisabledSkipsHook(void)
{
    KafkaSetup setup = {
        .topic = "eve",
        .topic_auto_create = false,
        .topic_partitions = 3,
    };
    KafkaTestTopicCreateCtx tctx = { 0 };
    FAIL_IF(KafkaMaybeCreateTopic(NULL, &setup, KafkaTestCreateTopicHook, &tctx) != 0);
    FAIL_IF(tctx.calls != 0);
    PASS;
}

static int KafkaTestTopicCreateEnabledUsesTopicPartitions(void)
{
    KafkaSetup setup = {
        .topic = "eve",
        .topic_auto_create = true,
        .topic_partitions = 3,
    };
    KafkaTestTopicCreateCtx tctx = { .ret = 0 };
    FAIL_IF(KafkaMaybeCreateTopic(NULL, &setup, KafkaTestCreateTopicHook, &tctx) != 0);
    FAIL_IF(tctx.calls != 1);
    FAIL_IF(tctx.partitions != 3);
    PASS;
}
```

Register:

```c
UtRegisterTest("KafkaTestTopicCreateDisabledSkipsHook", KafkaTestTopicCreateDisabledSkipsHook);
UtRegisterTest("KafkaTestTopicCreateEnabledUsesTopicPartitions",
        KafkaTestTopicCreateEnabledUsesTopicPartitions);
```

- [ ] **Step 2: Run tests to verify failure**

Run: `./src/suricata -u -U KafkaTestTopicCreate`

Expected: FAIL because `KafkaMaybeCreateTopic()` does not exist yet.

- [ ] **Step 3: Add topic creation hook helper**

Add near Kafka topic helpers:

```c
typedef int (*KafkaCreateTopicHookFunc)(void *hook_ctx, rd_kafka_t *rk,
        const char *topic_name, int num_partitions, int timeout_ms);

static int KafkaCreateTopicHook(void *hook_ctx, rd_kafka_t *rk,
        const char *topic_name, int num_partitions, int timeout_ms)
{
    return KafkaCreateTopic(rk, topic_name, num_partitions, timeout_ms);
}

static int KafkaMaybeCreateTopic(rd_kafka_t *rk, const KafkaSetup *setup,
        KafkaCreateTopicHookFunc create_hook, void *hook_ctx)
{
    if (!setup->topic_auto_create) {
        SCLogNotice("Kafka: topic auto-create disabled; startup does not require broker reachability");
        return 0;
    }
    return create_hook(hook_ctx, rk, setup->topic, setup->topic_partitions, 10000);
}
```

In `KafkaInit()`, replace unconditional topic creation:

```c
if (KafkaMaybeCreateTopic(ctx->rk, &ctx->setup, KafkaCreateTopicHook, NULL) != 0) {
    SCLogError("Kafka: Failed to create topic '%s'", ctx->setup.topic);
    goto error;
}
```

- [ ] **Step 4: Initialize all atomics and registry before producer start**

In `KafkaInit()`, after `KafkaParseConfig()` succeeds and before creating the producer:

```c
ctx->registry = KafkaQueueRegistryCreate();
if (ctx->registry == NULL) {
    SCLogError("Kafka: Failed to initialize queue registry");
    goto error;
}

SC_ATOMIC_INIT(ctx->stop_flag);
SC_ATOMIC_SET(ctx->stop_flag, 0);
SC_ATOMIC_INIT(ctx->messages_queued);
SC_ATOMIC_INIT(ctx->messages_sent);
SC_ATOMIC_INIT(ctx->messages_failed);
SC_ATOMIC_INIT(ctx->messages_dropped_queue);
SC_ATOMIC_INIT(ctx->messages_dropped_produce);
SC_ATOMIC_INIT(ctx->bytes_queued);
SC_ATOMIC_INIT(ctx->bytes_sent);
SC_ATOMIC_INIT(ctx->delivery_callback_count);
```

Remove creation of the old shared `ctx->ring_buffer`.

- [ ] **Step 5: Update produce and shutdown stats**

In `KafkaProduceWithRetry()`, replace `messages_dropped` increments with:

```c
SC_ATOMIC_ADD(ctx->messages_dropped_produce, 1);
```

In `KafkaDeinit()`, replace shutdown body with:

```c
SCLogInfo("Kafka: Initiating shutdown");
KafkaQueueRegistryCloseAll(ctx->registry);
SC_ATOMIC_SET(ctx->stop_flag, 1);
pthread_join(ctx->producer_thread, NULL);

KafkaQueueRegistryDestroy(ctx->registry);
ctx->registry = NULL;

rd_kafka_destroy(ctx->rk);
KafkaFreeConfig(&ctx->setup);

const uint64_t dropped_queue = SC_ATOMIC_GET(ctx->messages_dropped_queue);
const uint64_t dropped_produce = SC_ATOMIC_GET(ctx->messages_dropped_produce);
SCLogInfo("Kafka: Shutdown complete. Queued: %" PRIu64 ", Sent: %" PRIu64
          ", Failed: %" PRIu64 ", Dropped queue: %" PRIu64
          ", Dropped produce: %" PRIu64 ", Dropped total: %" PRIu64,
        SC_ATOMIC_GET(ctx->messages_queued),
        SC_ATOMIC_GET(ctx->messages_sent),
        SC_ATOMIC_GET(ctx->messages_failed),
        dropped_queue,
        dropped_produce,
        dropped_queue + dropped_produce);

SCFree(ctx);
```

- [ ] **Step 6: Run and commit**

Run: `./src/suricata -u -U KafkaTestTopicCreate`

Expected: PASS.

Run: `./src/suricata -u -U KafkaTestProduceWithRetryInternal`

Expected: PASS, preserving queue-full retry behavior.

```bash
git add src/output-eve-kafka.h src/output-eve-kafka.c
git commit -m "output/eve-kafka: make topic creation explicit"
```

### Task 6: Update YAML Documentation And Run Full Verification

**Files:**
- Modify: `suricata.yaml.in`
- Verify: `src/output-eve-kafka.c`, `src/output-eve-kafka.h`

- [ ] **Step 1: Update Kafka YAML comments**

In the Kafka block of `suricata.yaml.in`, replace the existing ring-buffer and partition comments with:

```yaml
      #  # Startup can succeed while brokers are unavailable when topic-auto-create is no.
      #  # Kafka reconnects are handled by librdkafka after Suricata starts.
      #  topic-auto-create: no          # Create topic during startup (default: no)
      #  topic-partitions: 1            # Used only when topic-auto-create is yes
      #  partition: -1                  # Message partition; -1 lets librdkafka choose
      #  ring-buffer-size: 65536        # Per-EVE-thread queue capacity
      #  ring-buffer-max-bytes: 67108864 # Per-EVE-thread queue byte budget
      #  max-drain-batch: 256           # Max messages drained per queue per producer round
      #  idle-poll-ms: 10               # Producer poll timeout when all queues are idle
```

Keep the existing librdkafka queue, timeout, retry, security, and compression examples after this block.

- [ ] **Step 2: Run formatting check for changed C code**

Run: `scripts/clang-format.sh check-branch --diffstat`

Expected: exit 0. If it reports changed files, run `scripts/clang-format.sh branch`, inspect the diff, and amend the current task commit before continuing.

- [ ] **Step 3: Run focused Kafka tests**

Run: `./src/suricata -u -U KafkaTest`

Expected: PASS for all Kafka unit tests.

- [ ] **Step 4: Run broader unit test command**

Run: `make check`

Expected: PASS. If the local environment lacks Kafka/librdkafka test prerequisites, capture the exact failing command and rerun the focused Kafka tests before handing off.

- [ ] **Step 5: Record manual validation commands for the PR description**

Use these exact commands or equivalent lab steps when a Kafka broker is available:

```bash
./src/suricata -c suricata.yaml -r qa/sample.pcap
docker compose -f qa/docker/kafka/docker-compose.yml up -d
./src/suricata -c suricata.yaml -r qa/sample.pcap
```

Record observations for:

- Suricata starts with Kafka down when `topic-auto-create: no`.
- New EVE messages deliver after Kafka starts.
- Queue drops increase while Kafka is stopped under high event volume.
- `topic-auto-create: yes` fails startup when create-topic ACLs are missing.

- [ ] **Step 6: Commit**

```bash
git add suricata.yaml.in src/output-eve-kafka.c src/output-eve-kafka.h
git commit -m "output/eve-kafka: document per-thread queue settings"
```

## Self-Review

- Spec coverage: per-thread queues are covered by Tasks 2 and 3; round-robin producer drain and non-blocking poll behavior by Task 4; startup and topic auto-create by Task 5; statistics by Tasks 3 and 5; YAML migration notes by Task 6.
- Placeholder scan: the plan has no deferred implementation steps or unnamed edge handling.
- Type consistency: queue entries use `SCEveKafkaQueueEntry`, queues use `SCEveKafkaQueue`, registries use `SCEveKafkaQueueRegistry`, and per-thread write state uses `SCEveKafkaThreadData` consistently across tasks.
