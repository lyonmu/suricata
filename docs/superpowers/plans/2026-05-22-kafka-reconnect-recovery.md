# Kafka Reconnect Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Kafka EVE output recover automatically after network restoration without restart, while keeping memory usage bounded during long outages.

**Architecture:** Extend `KafkaSetup` with reconnect/backoff and ring-buffer byte-budget settings, enforce dual ring-buffer limits (count and bytes), and add bounded retry for `RD_KAFKA_RESP_ERR__QUEUE_FULL` in producer thread. Keep loss-tolerant behavior and rely on librdkafka reconnects for normal outage recovery.

**Tech Stack:** C, Suricata output subsystem, librdkafka producer API, Suricata unit test framework.

---

### Task 1: Add Configuration Fields And Parsing Validation

**Files:**
- Modify: `src/output-eve-kafka.h`
- Modify: `src/output-eve-kafka.c`
- Modify: `suricata.yaml.in`
- Test: `src/output-eve-kafka.c` (existing unit tests section)

- [ ] **Step 1: Write the failing tests for new config defaults and validation**

```c
static int KafkaTestParseConfigDefaults(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) != 0);

    FAIL_IF(setup.ring_buffer_max_bytes != 67108864ULL);
    FAIL_IF(setup.reconnect_backoff_ms != 100);
    FAIL_IF(setup.reconnect_backoff_max_ms != 10000);
    FAIL_IF(setup.retry_backoff_max_ms != 1000);
    FAIL_IF(setup.queue_buffering_max_kbytes != 131072);

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

static int KafkaTestParseConfigInvalidReconnectBackoffOrder(void)
{
    SCConfNode *node = KafkaTestCreateBaseConfig();
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfSet("kafka.reconnect-backoff-ms", "1000"));
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
    FAIL_IF_NOT(SCConfSet("kafka.retry-backoff-ms", "1000"));
    FAIL_IF_NOT(SCConfSet("kafka.retry-backoff-max-ms", "100"));

    KafkaSetup setup = { 0 };
    FAIL_IF(KafkaParseConfig(node, &setup) == 0);

    KafkaTestDestroyBaseConfig(&setup);
    PASS;
}
```

- [ ] **Step 2: Run test to verify failures**

Run: `./src/suricata -u -U KafkaTestParseConfigDefaults`
Expected: FAIL because new struct fields and parsing paths do not exist yet.

- [ ] **Step 3: Add new `KafkaSetup` fields and defaults**

```c
/* src/output-eve-kafka.h */
#define KAFKA_RING_BUFFER_MAX_BYTES_DEFAULT 67108864ULL
#define KAFKA_RECONNECT_BACKOFF_MS          100
#define KAFKA_RECONNECT_BACKOFF_MAX_MS      10000
#define KAFKA_RETRY_BACKOFF_MAX_MS          1000
#define KAFKA_QUEUE_BUFFERING_MAX_KBYTES    131072

typedef struct KafkaSetup_ {
    ...
    uint64_t ring_buffer_max_bytes;
    int reconnect_backoff_ms;
    int reconnect_backoff_max_ms;
    int retry_backoff_max_ms;
} KafkaSetup;
```

```c
/* src/output-eve-kafka.c in KafkaParseConfig() */
setup->ring_buffer_max_bytes = KAFKA_RING_BUFFER_MAX_BYTES_DEFAULT;
setup->reconnect_backoff_ms = KAFKA_RECONNECT_BACKOFF_MS;
setup->reconnect_backoff_max_ms = KAFKA_RECONNECT_BACKOFF_MAX_MS;
setup->retry_backoff_max_ms = KAFKA_RETRY_BACKOFF_MAX_MS;
setup->queue_buffering_max_kbytes = KAFKA_QUEUE_BUFFERING_MAX_KBYTES;

if (SCConfGetChildValueInt(conf, "ring-buffer-max-bytes", &intval)) { ... }
if (SCConfGetChildValueInt(conf, "reconnect-backoff-ms", &intval)) { ... }
if (SCConfGetChildValueInt(conf, "reconnect-backoff-max-ms", &intval)) { ... }
if (SCConfGetChildValueInt(conf, "retry-backoff-max-ms", &intval)) { ... }

if (setup->reconnect_backoff_max_ms < setup->reconnect_backoff_ms) { ...goto error; }
if (setup->retry_backoff_max_ms < setup->retry_backoff_ms) { ...goto error; }
```

- [ ] **Step 4: Wire new fields to librdkafka config and YAML docs**

```c
/* src/output-eve-kafka.c in KafkaCreateRdKafkaConf() */
snprintf(buf, sizeof(buf), "%d", setup->reconnect_backoff_ms);
rd_kafka_conf_set(conf, "reconnect.backoff.ms", buf, errbuf, sizeof(errbuf));

snprintf(buf, sizeof(buf), "%d", setup->reconnect_backoff_max_ms);
rd_kafka_conf_set(conf, "reconnect.backoff.max.ms", buf, errbuf, sizeof(errbuf));

snprintf(buf, sizeof(buf), "%d", setup->retry_backoff_max_ms);
rd_kafka_conf_set(conf, "retry.backoff.max.ms", buf, errbuf, sizeof(errbuf));
```

```yaml
# suricata.yaml.in Kafka comment block
#  ring-buffer-max-bytes: 67108864
#  queue-buffering-max-kbytes: 131072
#  reconnect-backoff-ms: 100
#  reconnect-backoff-max-ms: 10000
#  retry-backoff-max-ms: 1000
```

- [ ] **Step 5: Register tests and run them**

Run: `./src/suricata -u -U KafkaTestParseConfig`
Expected: PASS for all Kafka parse config tests.

- [ ] **Step 6: Commit**

```bash
git add src/output-eve-kafka.h src/output-eve-kafka.c suricata.yaml.in
git commit -m "output/eve-kafka: add reconnect and memory bound config"
```

### Task 2: Enforce Ring Buffer Byte Budget

**Files:**
- Modify: `src/output-eve-kafka.h`
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c` (unit tests section)

- [ ] **Step 1: Write failing ring-buffer byte-budget tests**

```c
static int KafkaTestRingBufferByteBudgetDropOldest(void)
{
    SCEveKafkaRingBuffer *rb = RingBufferInit(8, 12);
    FAIL_IF_NULL(rb);

    FAIL_IF(RingBufferPush(rb, SCStrdup("aaaa"), 4) != 0);
    FAIL_IF(RingBufferPush(rb, SCStrdup("bbbb"), 4) != 0);
    FAIL_IF(RingBufferPush(rb, SCStrdup("cccc"), 4) != 0);
    FAIL_IF(RingBufferPush(rb, SCStrdup("dddd"), 4) != 0);

    /* 4 x 4 bytes exceeds 12 bytes, oldest should be dropped */
    FAIL_IF(SC_ATOMIC_GET(rb->dropped) == 0);

    RingBufferDestroy(rb);
    PASS;
}

static int KafkaTestRingBufferByteBudgetOversizedDrop(void)
{
    SCEveKafkaRingBuffer *rb = RingBufferInit(8, 4);
    FAIL_IF_NULL(rb);

    FAIL_IF(RingBufferPush(rb, SCStrdup("123456"), 6) != -1);
    FAIL_IF(SC_ATOMIC_GET(rb->dropped) != 1);

    RingBufferDestroy(rb);
    PASS;
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `./src/suricata -u -U KafkaTestRingBufferByteBudget`
Expected: FAIL because ring buffer byte-budget API does not exist yet.

- [ ] **Step 3: Add byte accounting to ring buffer struct and init**

```c
typedef struct SCEveKafkaRingBuffer_ {
    ...
    uint64_t bytes;
    uint64_t max_bytes;
} SCEveKafkaRingBuffer;

static SCEveKafkaRingBuffer *RingBufferInit(uint32_t size, uint64_t max_bytes)
{
    ...
    rb->bytes = 0;
    rb->max_bytes = max_bytes;
}
```

- [ ] **Step 4: Enforce byte-budget in push and pop paths**

```c
/* RingBufferPush() */
if (len > rb->max_bytes) {
    SCFree(data);
    SC_ATOMIC_ADD(rb->dropped, 1);
    SCSpinUnlock(&rb->lock);
    return -1;
}

while ((next_head == rb->tail) || (rb->bytes + len > rb->max_bytes)) {
    SCEveKafkaRingBufferEntry *old_entry = &rb->entries[rb->tail];
    if (old_entry->data != NULL) {
        rb->bytes -= old_entry->len;
        ...
    }
    rb->tail = (rb->tail + 1) % rb->size;
}

entry->data = data;
entry->len = len;
rb->bytes += len;
```

```c
/* RingBufferPop() */
entry->data = rb->entries[rb->tail].data;
entry->len = rb->entries[rb->tail].len;
rb->bytes -= entry->len;
```

- [ ] **Step 5: Update call sites and startup logs**

```c
ctx->ring_buffer = RingBufferInit(ctx->setup.ring_buffer_size,
                                  ctx->setup.ring_buffer_max_bytes);

SCLogNotice("Kafka producer initialized (... ring_buffer_size: %d, ring_buffer_max_bytes: %" PRIu64 ", queue_buffering_max_kbytes: %d ...)",
            ...);
```

- [ ] **Step 6: Run tests and commit**

Run: `./src/suricata -u -U KafkaTestRingBuffer`
Expected: PASS for basic, overflow, and byte-budget tests.

```bash
git add src/output-eve-kafka.h src/output-eve-kafka.c
git commit -m "output/eve-kafka: enforce ring buffer byte budget"
```

### Task 3: Add Bounded Retry For Queue Full

**Files:**
- Modify: `src/output-eve-kafka.c`
- Test: `src/output-eve-kafka.c` (unit tests section)

- [ ] **Step 1: Write failing helper-level test for bounded retry policy**

```c
static int KafkaTestQueueFullRetryLimit(void)
{
    FAIL_IF(KafkaQueueFullRetryBudget() != 3);
    PASS;
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `./src/suricata -u -U KafkaTestQueueFullRetryLimit`
Expected: FAIL because helper does not exist.

- [ ] **Step 3: Extract and implement helper used by producer loop**

```c
static inline int KafkaQueueFullRetryBudget(void)
{
    return 3;
}

static rd_kafka_resp_err_t KafkaProduceWithQueueFullRetry(SCEveKafkaContext *ctx,
        SCEveKafkaRingBufferEntry *entry)
{
    for (int i = 0; i <= KafkaQueueFullRetryBudget(); i++) {
        rd_kafka_resp_err_t ret = rd_kafka_producev(...);
        if (ret == RD_KAFKA_RESP_ERR_NO_ERROR) {
            return ret;
        }
        if (ret != RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            return ret;
        }
        rd_kafka_poll(ctx->rk, 10);
    }
    return RD_KAFKA_RESP_ERR__QUEUE_FULL;
}
```

- [ ] **Step 4: Replace direct `rd_kafka_producev()` call in producer thread**

```c
rd_kafka_resp_err_t ret = KafkaProduceWithQueueFullRetry(ctx, &entry);
if (ret != RD_KAFKA_RESP_ERR_NO_ERROR) {
    if (ret == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
        SCLogWarning("Kafka internal queue full after retries, dropping message");
    } else {
        SCLogError("Failed to produce message: %s", rd_kafka_err2str(ret));
    }
    SCFree(entry.data);
    SC_ATOMIC_ADD(ctx->messages_dropped, 1);
}
```

- [ ] **Step 5: Run Kafka unit tests and commit**

Run: `./src/suricata -u -U KafkaTest`
Expected: PASS for all Kafka unit tests.

```bash
git add src/output-eve-kafka.c
git commit -m "output/eve-kafka: retry queue full before dropping"
```

### Task 4: End-To-End Verification And Final Polish

**Files:**
- Modify: `src/output-eve-kafka.c`
- Modify: `suricata.yaml.in`
- Test: runtime/manual validation

- [ ] **Step 1: Ensure init log exposes memory and reconnect bounds**

```c
SCLogNotice("Kafka producer initialized (brokers: %s, topic: %s, ring_buffer_size: %d, ring_buffer_max_bytes: %" PRIu64 ", queue_buffering_max_kbytes: %d, reconnect_backoff_ms: %d, reconnect_backoff_max_ms: %d, retry_backoff_ms: %d, retry_backoff_max_ms: %d, linger_ms: %dms)",
    ...);
```

- [ ] **Step 2: Build and run targeted tests**

Run: `make -j$(nproc)`
Expected: build succeeds.

Run: `./src/suricata -u -U KafkaTest`
Expected: Kafka unit tests pass.

- [ ] **Step 3: Manual outage-recovery validation**

Run sequence:

```bash
# terminal 1
SC_LOG_LEVEL=Info ./src/suricata -c suricata.yaml -r /path/to/test.pcap

# terminal 2 (simulate outage)
iptables -A OUTPUT -p tcp --dport 9092 -j DROP
sleep 60
iptables -D OUTPUT -p tcp --dport 9092 -j DROP
```

Expected:
- During outage: queue-full/dropped warnings appear, Suricata keeps running.
- After restore: new messages resume to Kafka without Suricata restart.

- [ ] **Step 4: Final commit**

```bash
git add src/output-eve-kafka.c src/output-eve-kafka.h suricata.yaml.in
git commit -m "output/eve-kafka: recover after outages with bounded memory"
```

## Spec Coverage Check

- Automatic recovery without restart: Task 1 backoff config + Task 3 retry policy.
- Memory bounded during long outages: Task 2 byte-budget + Task 1 reduced queue default.
- Preserve loss-tolerant model: Task 2 drop-oldest and oversized drop + Task 3 bounded retry then drop.
- Operator clarity: Task 4 startup logging and YAML doc updates.

## Placeholder Scan

No placeholder markers (`TBD`, `TODO`, `implement later`) are present. Each task lists exact files, concrete code snippets, and runnable commands with expected outcomes.

## Type Consistency Check

New field names are consistent across tasks:

- `ring_buffer_max_bytes`
- `reconnect_backoff_ms`
- `reconnect_backoff_max_ms`
- `retry_backoff_max_ms`

Helper names are consistent:

- `KafkaQueueFullRetryBudget()`
- `KafkaProduceWithQueueFullRetry()`
