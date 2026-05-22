# Kafka High-Throughput Queue Follow-Up Design

## Context

The Kafka high-throughput queue refactor is mostly implemented, but the current
code intentionally differs from the original plan in two areas and still has two
behavioral gaps.

Current behavior to preserve:

- `topic-partitions` defaults to `3`.
- `topic-auto-create: yes` attempts topic creation, logs a warning on failure,
  and continues startup.

Behavioral gaps to fix:

- The configured Kafka `partition` value is parsed but not passed to
  `rd_kafka_producev()`.
- Queue drop-oldest loss is counted on the per-thread queue but not included in
  the global `messages_dropped_queue` shutdown statistic.

This follow-up keeps the existing compatibility behavior and fixes only the
clear runtime bugs.

## Goals

- Preserve current startup compatibility and topic partition defaults.
- Make configured message partitioning effective.
- Make global queue drop statistics include every queue-layer loss.
- Keep the Kafka write path non-blocking with respect to broker availability and
  librdkafka backpressure.
- Add focused unit coverage for the corrected behavior.

## Non-Goals

- Do not change `topic-partitions` default from `3` back to `1`.
- Do not make topic creation failure fatal during startup.
- Do not introduce disk persistence, guaranteed delivery, or a new queue
  architecture.
- Do not refactor unrelated Kafka configuration or security handling.

## Design

### Partition Handling

`KafkaSetup.partition` remains the source of truth for the configured target
partition. `-1` continues to mean `RD_KAFKA_PARTITION_UA`, letting librdkafka
choose the partition.

The producer drain path should pass the configured partition through the full
call chain:

1. `KafkaProducerThread()` calls `KafkaDrainQueuesInternal()` with
   `ctx->setup.partition`.
2. `KafkaDrainQueuesInternal()` passes that partition to the produce hook for
   each drained entry.
3. `KafkaDrainProduceHook()` includes `RD_KAFKA_V_PARTITION(partition)` in
   `rd_kafka_producev()`.

If librdkafka rejects a configured partition, the existing produce failure path
counts the message in `messages_dropped_produce` and releases the payload.

### Queue Drop Statistics

`messages_dropped_queue` should count all queue-layer drops:

- oversized payload rejected by `KafkaQueuePush()`;
- write rejected because the queue is closed;
- allocation failure while copying into the queue;
- older messages discarded by drop-oldest while making space for a new message.

The queue should report the number of messages dropped during each push
operation. `KafkaWrite()` then increments `messages_dropped_queue` by that
reported value and still increments `messages_queued` when the new message is
accepted. This preserves the current non-blocking output behavior while making
the final global statistics match actual loss.

The per-queue `dropped` counter remains useful for unit tests and debug
inspection, but shutdown reporting must not rely on scanning queue internals.

### Startup And Topic Creation

The follow-up keeps the current compatibility behavior:

- `topic-auto-create: no`: skip topic creation and allow startup without broker
  reachability.
- `topic-auto-create: yes`: attempt topic creation; if it fails, log a warning
  and continue startup.

The design intentionally updates the follow-up plan to document this behavior
instead of restoring the earlier fail-fast requirement.

## Testing

Focused unit tests should cover the changed behavior:

- `KafkaTestKafkaWriteCountsDropOldest`: create a small queue, write enough
  messages through `KafkaWrite()` to force drop-oldest, and verify
  `messages_dropped_queue` includes the discarded messages.
- `KafkaTestDrainUsesConfiguredPartition`: drain a queue with a fake produce
  hook and verify the hook receives the configured partition instead of
  `RD_KAFKA_PARTITION_UA`.
- Existing queue primitive tests continue to validate per-queue `dropped`.
- Existing topic-create tests keep the current non-fatal startup policy.

Verification commands:

```bash
make -j2
./src/suricata -u -U KafkaTest
scripts/clang-format.sh check-branch --diffstat
```

If the local build lacks `--enable-unittests`, record that blocker and run the
build command. If `git-clang-format` is unavailable, record that blocker rather
than claiming the formatting check passed.

## Implementation Notes

The implementation plan should keep changes narrow:

- Extend `KafkaQueuePush()` with a drop-count out parameter or equivalent small
  result structure.
- Update only Kafka queue, write, and drain call sites required by the new
  signatures.
- Add focused unit tests near the existing Kafka tests.
- Update docs under `docs/superpowers/plans/` only as needed to record the
  accepted follow-up semantics.
