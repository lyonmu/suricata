# Kafka High-Throughput Queue Refactor Design

## Problem

The current Kafka EVE output uses one shared ring buffer and one producer
thread. It decouples Suricata packet processing from Kafka, but several issues
remain:

- The producer loop calls `rd_kafka_poll(ctx->rk, 100)` on every iteration,
  which can throttle throughput even when messages are available.
- Kafka output initialization always tries to create the topic, so startup can
  fail when Kafka is unreachable or the Kafka credentials do not have topic
  administration privileges.
- The `partition` option is ambiguous: the YAML describes automatic partitioning,
  while the implementation uses the value as the topic creation partition count.
- Ring buffer drops are tracked in the ring buffer but not in the final global
  Kafka dropped statistics.
- Numeric config parsing validates minimum values but not maximum values before
  casting to `int`.
- `stop_flag` is assigned through `SC_ATOMIC_SET()` without first using the
  project's `SC_ATOMIC_INIT()` macro.
- A single shared ring buffer lock can become a contention point in threaded EVE
  logging mode.

The goal is a higher-throughput design that preserves the original recovery
policy: Suricata availability is more important than retaining every Kafka
message during Kafka outages.

## Scope

This design covers the Kafka EVE output implementation in:

- `src/output-eve-kafka.c`
- `src/output-eve-kafka.h`
- Kafka configuration examples in `suricata.yaml.in`

It does not add disk persistence, exactly-once delivery, transactional Kafka
production, or guaranteed delivery during Kafka outages.

## Design Goals

- Avoid blocking packet processing on Kafka availability or Kafka backpressure.
- Remove the global queue lock from the hot write path in threaded EVE mode.
- Keep Kafka output memory bounded by message count and byte count.
- Prefer recent messages when Kafka is slow or unavailable.
- Let librdkafka handle normal broker reconnects.
- Allow Suricata to start when Kafka is temporarily unreachable.
- Keep the implementation testable without requiring a live Kafka broker.

## Architecture

Replace the single shared ring buffer with per-EVE-thread bounded queues and a
single Kafka producer thread.

```text
EVE thread 0 -> queue 0 \
EVE thread 1 -> queue 1  -> Kafka producer thread -> librdkafka queue -> broker
EVE thread N -> queue N /
```

Each EVE output thread writes only to its own queue. The Kafka producer thread
round-robin drains all registered queues and submits messages to librdkafka.

The first implementation should use a small per-queue lock rather than a fully
lock-free queue. This keeps lifecycle handling simple during thread registration,
shutdown, and test setup, while still removing the current global lock
contention. The hot path contention becomes one writer and one reader per queue.

## Components

### KafkaQueue

`KafkaQueue` is the per-thread bounded queue. It owns:

- Entry array.
- Head and tail indexes.
- Entry count or empty/full state.
- Current buffered bytes.
- Maximum buffered bytes.
- Per-queue counters for pushed, popped, and dropped messages.
- A lightweight lock for writer/reader synchronization.
- A closing flag that prevents new writes during shutdown.

The queue enforces two limits:

- `ring-buffer-size`: maximum queued messages per EVE thread.
- `ring-buffer-max-bytes`: maximum queued payload bytes per EVE thread.

When a new message would exceed either limit, the queue drops oldest messages
until the new message fits. If a single message is larger than the byte budget,
it drops that message directly.

The drop-oldest policy remains intentional. During Kafka outages, fresh EVE
events are more useful than stale outage-period events once Kafka recovers.

### KafkaQueueRegistry

`KafkaQueueRegistry` manages all per-thread queues for a Kafka EVE output
instance.

- `KafkaThreadInit()` allocates and registers one queue, then stores it in
  `thread_data`.
- `KafkaWrite()` uses the queue from `thread_data` instead of a global queue.
- `KafkaThreadDeinit()` marks the queue closed so no more writes are accepted.
- The producer thread traverses the registry to drain queues.
- `KafkaDeinit()` stops the producer thread, drains remaining queues, and frees
  the registry.

The registry may use one lock for queue list membership changes. This lock is
not on the per-event write path after a thread has its queue pointer.

### KafkaProducerLoop

The producer loop drains queues in bounded batches.

Recommended defaults:

- `max-drain-batch`: 256 messages per queue per round.
- `idle-poll-ms`: 10ms when no messages are available.
- Queue-full retry: keep the existing 3 retries with 10ms poll intervals.

Loop behavior:

1. Iterate queues in round-robin order.
2. Pop up to `max-drain-batch` messages from each queue.
3. Produce each message with `KafkaProduceWithRetry()`.
4. Call `rd_kafka_poll(ctx->rk, 0)` after active batches to process delivery
   callbacks without blocking throughput.
5. If no queue produced work in a loop, call `rd_kafka_poll(ctx->rk,
   idle-poll-ms)` so librdkafka callbacks still run without busy-waiting.

This removes the current per-message `rd_kafka_poll(..., 100)` throttle while
still allowing librdkafka to make progress.

### KafkaConfig

Keep existing option names where possible for compatibility, but clarify their
meaning.

- `ring-buffer-size`: per-thread queue entry capacity.
- `ring-buffer-max-bytes`: per-thread queue payload byte budget.
- `queue-buffering-max-messages`: librdkafka queue message limit.
- `queue-buffering-max-kbytes`: librdkafka queue byte limit.
- `partition`: message partition for `rd_kafka_producev()`; `-1` means
  automatic partitioning. It is no longer used as a topic creation partition
  count.
- `topic-auto-create`: default `no`. If `yes`, Kafka initialization attempts to
  create the topic.
- `topic-partitions`: partition count used only when `topic-auto-create: yes`.
  Default `1`.
- `max-drain-batch`: maximum messages drained from one queue per producer loop
  round. Default `256`.
- `idle-poll-ms`: producer-loop poll timeout when no messages are available.
  Default `10`.

All numeric values parsed as `intmax_t` must be checked against both a minimum
and the target type maximum before casting to `int` or `uint32_t`.

### KafkaStats

Use global context counters for final reporting and operational visibility.

Recommended counters:

- `messages_queued`
- `messages_sent`
- `messages_failed`
- `messages_dropped_queue`
- `messages_dropped_produce`
- `bytes_queued`
- `bytes_sent`
- `delivery_callback_count`

Final shutdown logs should include total dropped messages and the split between
queue drops and produce drops.

Queue-level counters are still useful for unit tests and debug logs, but global
statistics must include queue drops so operators see the real loss count.

## Startup Behavior

Default startup must not require broker reachability.

`KafkaInit()` should:

1. Parse and validate config.
2. Initialize atomics, including `stop_flag` with `SC_ATOMIC_INIT()`.
3. Create the queue registry.
4. Create the librdkafka producer.
5. Optionally create the topic only when `topic-auto-create: yes`.
6. Start the producer thread.

If Kafka is unreachable and `topic-auto-create` is disabled, initialization
should still succeed. librdkafka will reconnect later according to its configured
reconnect backoff.

If `topic-auto-create: yes` is configured and topic creation fails, Kafka output
initialization should fail because the user explicitly requested a startup-time
administrative operation.

## Write Path

`KafkaWrite()` should remain non-blocking with respect to Kafka.

Behavior:

1. Validate `ctx` and `thread_data` queue pointer.
2. Allocate and copy the EVE JSON buffer.
3. Push into the per-thread queue.
4. If allocation fails, the queue is closed, or the message is dropped by queue
   policy, update global drop counters and return 0.

The EVE filetype write API uses `0` for successful handling. Dropping due to
Kafka backpressure is an expected policy outcome, not an output API failure, so
it should return 0 to avoid back-pressuring packet processing.

## Produce Path

`KafkaProduceWithRetry()` should retain the existing ownership model:

- On successful `rd_kafka_producev()` with `RD_KAFKA_MSG_F_FREE`, librdkafka owns
  the message payload.
- On failure, the caller remains responsible for freeing the message payload.

When `RD_KAFKA_RESP_ERR__QUEUE_FULL` is returned:

1. Call `rd_kafka_poll(ctx->rk, 10)`.
2. Retry up to 3 times.
3. If all attempts fail, free the payload and increment
   `messages_dropped_produce`.

Other `rd_kafka_producev()` errors should log an error, free the payload,
increment `messages_dropped_produce`, and continue.

## Shutdown Behavior

Shutdown should be bounded and deterministic.

1. EVE thread deinit closes individual queues as threads stop.
2. `KafkaDeinit()` sets `stop_flag`.
3. The producer thread exits its active loop, drains all registered queues, then
   calls `rd_kafka_flush()` with a bounded timeout.
4. If the flush times out, log the remaining librdkafka queue length and
   continue shutdown.
5. Destroy queues, registry, producer, and config.

The producer thread should not destroy queues while EVE threads may still hold
queue pointers. Queue destruction belongs after output thread deinitialization
and producer shutdown are complete.

## Error Handling

- Config parsing failures fail initialization with clear `SCLogError()` output.
- Unknown enum-like values should either fail fast or clearly warn and use the
  documented default. For Kafka operational settings, fail-fast is preferred
  when ambiguity could hide misconfiguration.
- Queue drops should be logged sparingly, using counters for high-volume loss.
- `QUEUE_FULL` after bounded retry should be warning-level because it is expected
  during overload or Kafka outage.
- Delivery callback failures continue to increment `messages_failed`.
- Topic creation errors are fatal only when `topic-auto-create: yes`.

## Testing

Unit tests should cover:

- Per-thread queue basic push/pop.
- Queue count-budget drop-oldest behavior.
- Queue byte-budget drop-oldest behavior.
- Oversized single-message drop.
- Closed queue rejects writes and updates drop counters.
- Registry registration of multiple queues.
- Round-robin drain fairness so a busy first queue does not starve later queues.
- Producer loop helper uses non-blocking `poll(0)` after active work and
  `idle-poll-ms` when idle.
- Queue-full retry behavior remains covered by hook-based tests.
- Config defaults:
  - `topic-auto-create` defaults to `no`.
  - `partition` defaults to automatic message partitioning.
  - `topic-partitions` defaults to `1`.
  - `max-drain-batch` defaults to `256`.
  - `idle-poll-ms` defaults to `10`.
- Config validation rejects values above target type maximum before casts.
- Config validation rejects invalid backoff ordering.

Manual validation should cover:

1. Start Suricata with Kafka output while Kafka is down and
   `topic-auto-create: no`; confirm Suricata starts.
2. Start Kafka after Suricata; confirm new EVE messages are delivered without a
   Suricata restart.
3. Stop Kafka during high event generation; confirm memory remains bounded and
   queue drops increase.
4. Restart Kafka; confirm new messages resume.
5. Run with `topic-auto-create: yes` against an account without create-topic
   ACL; confirm initialization fails with a clear error.
6. Run threaded EVE logging under high event rate; compare queue drops and CPU
   utilization against the previous single shared ring buffer implementation.

## Documentation

Update `suricata.yaml.in` comments to document:

- Kafka output can start while brokers are unavailable when topic auto-create is
  disabled.
- Queue limits are per EVE output thread.
- `partition` controls message partitioning only.
- `topic-auto-create` is off by default and requires broker admin privileges.
- The operational trade-off remains availability over guaranteed delivery.

## Migration Notes

Existing configurations using `partition` as an intended message partition will
start matching the documented meaning. Existing configurations relying on the
old implicit topic creation partition count must switch to:

```yaml
topic-auto-create: yes
topic-partitions: <count>
```

Because implicit topic creation can break startup during outages or under
restricted ACLs, disabling it by default is the safer behavior for Suricata.

## Out Of Scope

- Disk-backed queues.
- Producer recreation after librdkafka fatal errors.
- Kafka transactions.
- Exactly-once semantics.
- Cross-process persistence across Suricata restarts.
