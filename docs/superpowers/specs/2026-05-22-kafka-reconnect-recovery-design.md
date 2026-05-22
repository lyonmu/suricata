# Kafka Reconnect Recovery Design

## Problem

Suricata's Kafka EVE output can stop producing messages after a Kafka network
failure. In the observed failure mode, Kafka output only resumes after manually
restarting Suricata.

The required behavior is:

- Suricata must keep running when Kafka is unreachable.
- Messages generated while Kafka is unreachable may be dropped.
- After network connectivity to Kafka recovers, new EVE messages must resume
  being produced without restarting Suricata.
- Kafka outages must not allow unbounded memory growth or cause Suricata to
  fail with OOM under high traffic.

## Scope

This design covers the existing C Kafka EVE output implementation in:

- `src/output-eve-kafka.c`
- `src/output-eve-kafka.h`
- Kafka-related configuration examples in `suricata.yaml.in`

This design does not add disk persistence, exactly-once delivery, or guaranteed
delivery of messages generated during Kafka outages.

## Current Architecture

The current Kafka output path has three stages:

1. EVE writer threads call `KafkaWrite()`.
2. `KafkaWrite()` copies the JSON event into a local ring buffer.
3. `KafkaProducerThread()` pops entries from the ring buffer and calls
   `rd_kafka_producev()`.

librdkafka owns broker connections, message batching, delivery callbacks, and
broker reconnect behavior after messages enter the librdkafka producer queue.

The current local ring buffer is bounded by message count and drops the oldest
entry when full. librdkafka is bounded by `queue.buffering.max.messages` and
`queue.buffering.max.kbytes`. However, the current default
`queue-buffering-max-kbytes` is 1GB, which is too high for a non-persistent
"drop during outage" mode under high traffic.

## Design Goals

- Prefer Suricata availability over Kafka log retention.
- Bound memory used by Kafka output during long Kafka outages.
- Let librdkafka perform normal reconnects instead of rebuilding the producer
  for ordinary network failures.
- Drop old outage-period messages when buffers are full.
- Resume sending new messages automatically once Kafka connectivity returns.
- Keep the first implementation small and isolated.

## Non-Goals

- Do not preserve all messages generated while Kafka is unavailable.
- Do not block packet processing on Kafka availability.
- Do not introduce a disk-backed queue.
- Do not rebuild the librdkafka producer unless later evidence shows the client
  has entered a fatal unrecoverable state.

## Proposed Approach

Use a recovery-first and memory-bounded design:

1. Explicitly configure librdkafka reconnect and retry backoff.
2. Add a byte budget to the Suricata-side ring buffer.
3. Reduce the default librdkafka queue memory limit.
4. Change `RD_KAFKA_RESP_ERR__QUEUE_FULL` handling from immediate drop to
   short bounded retry, then drop.
5. Keep "drop oldest" behavior so recovered output favors recent messages.

## Configuration

Add these Kafka setup fields and YAML options:

- `ring-buffer-max-bytes`
  - Default: `67108864` bytes, 64MB.
  - Limits bytes held by the local Suricata ring buffer.
  - A value must be greater than zero.

- `reconnect-backoff-ms`
  - Default: `100`.
  - Maps to librdkafka `reconnect.backoff.ms`.
  - A value must be greater than zero.

- `reconnect-backoff-max-ms`
  - Default: `10000`.
  - Maps to librdkafka `reconnect.backoff.max.ms`.
  - A value must be greater than zero and greater than or equal to
    `reconnect-backoff-ms`.

- `retry-backoff-max-ms`
  - Default: `1000`.
  - Maps to librdkafka `retry.backoff.max.ms`.
  - A value must be greater than or equal to `retry-backoff-ms`.

Change the default for:

- `queue-buffering-max-kbytes`
  - Old default: `1048576` KB, 1GB.
  - New default: `131072` KB, 128MB.
  - Users with high memory budgets can still configure a larger value.

Keep these existing options:

- `queue-buffering-max-messages`
- `message-timeout-ms`
- `socket-timeout-ms`
- `metadata-max-age-ms`
- `retry-backoff-ms`
- `linger-ms`

## Memory Bound

Kafka output memory is bounded by:

- Local ring buffer entry storage up to `ring-buffer-max-bytes`, plus entry array
  overhead from `ring-buffer-size`.
- librdkafka producer queue up to `queue-buffering-max-kbytes`.
- librdkafka internal overhead.

With recommended defaults, the intentional buffering budget is approximately:

- 64MB local ring buffer payloads.
- 128MB librdkafka queued payloads.

The implementation should log these configured limits at startup so operators
can see the worst-case Kafka output memory budget from logs.

## Ring Buffer Behavior

The ring buffer should enforce both limits:

- `ring-buffer-size` limits number of entries.
- `ring-buffer-max-bytes` limits total payload bytes.

When adding a new message would exceed either limit, the ring buffer drops the
oldest entries until the new message can fit or the buffer becomes empty.

If a single message is larger than `ring-buffer-max-bytes`, drop that message
and increment the dropped counter. This prevents one oversized event from
invalidating the memory bound.

The existing drop-oldest policy remains intentional. During Kafka outages, old
messages become less useful than recent messages once the network recovers.

## Producer Queue Full Behavior

When `rd_kafka_producev()` returns `RD_KAFKA_RESP_ERR__QUEUE_FULL`:

1. Call `rd_kafka_poll(ctx->rk, 10)` to let librdkafka process callbacks and
   free queue space.
2. Retry producing the same message up to 3 times.
3. If all retries fail, free the message, increment `messages_dropped`, and
   continue.

The producer thread must not block indefinitely waiting for Kafka. Bounded retry
keeps output responsive and prevents Kafka outages from back-pressuring packet
processing.

## Reconnect Behavior

Ordinary Kafka network failures should be left to librdkafka:

- librdkafka detects broker connection failure.
- librdkafka retries messages that are still within `message.timeout.ms`.
- librdkafka reconnects using configured reconnect backoff.
- After network recovery, new messages accepted by `rd_kafka_producev()` should
  be delivered normally.

The first implementation should not add producer destroy/recreate logic. If
future testing shows librdkafka can enter a fatal state in this integration, add
an `error_cb` and producer recreation as a separate follow-up design.

## Error Handling

- Config parsing failures should fail Kafka output initialization.
- Invalid numeric values should produce clear `SCLogError()` messages.
- `QUEUE_FULL` after bounded retry should be logged at warning level, not error
  level, because it is expected during Kafka outages or overload.
- Other `rd_kafka_producev()` errors should keep current behavior: log, drop the
  message, increment `messages_dropped`, and continue.
- Delivery callback failures should continue to increment `messages_failed`.

## Testing

Unit tests should cover:

- Default parsing for new config fields.
- Invalid `ring-buffer-max-bytes`.
- Invalid reconnect and retry max backoff values.
- Ring buffer byte-budget enforcement.
- Oversized single message drop.
- Existing ring buffer count overflow behavior.

If practical, isolate the queue-full retry behavior into a helper so it can be
unit tested without a real Kafka broker. If direct mocking is too invasive,
cover the helper-level logic where possible and verify the full reconnect path
manually.

Manual validation should cover:

1. Start Kafka and Suricata with Kafka EVE output enabled.
2. Confirm messages are produced.
3. Break network connectivity to Kafka or stop the broker.
4. Generate enough events to exceed the configured buffering budget.
5. Confirm Suricata memory remains bounded and messages are dropped.
6. Restore Kafka connectivity.
7. Confirm new messages resume without restarting Suricata.

## Documentation

Update `suricata.yaml.in` Kafka comments to describe:

- Reconnect backoff options.
- `ring-buffer-max-bytes`.
- Lower default `queue-buffering-max-kbytes`.
- The operational trade-off: this output mode prioritizes Suricata availability
  and automatic recovery over retaining all messages during Kafka outages.

## Open Follow-Up

A future enhancement may add fatal-error detection and producer recreation if
tests or field reports show librdkafka reaches an unrecoverable state after
specific failures. That is intentionally out of scope for this change because
ordinary network recovery should be handled by librdkafka's reconnect logic.
