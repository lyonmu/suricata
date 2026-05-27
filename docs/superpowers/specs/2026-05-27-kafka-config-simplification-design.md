# Kafka Config Simplification Design

## Problem

The Kafka EVE output exposes several low-frequency librdkafka tuning options in
`suricata.yaml.in`. Most deployments should not need to tune these values, and
the large option surface makes misconfiguration easier.

One current option, `partition`, can also cause runtime delivery failures. When
it is set to a fixed partition that does not exist on the target topic,
librdkafka reports delivery failures such as:

```text
Kafka message delivery failed: Local: Unknown partition
```

The goal is to remove fixed partition selection, keep Kafka production on
librdkafka automatic partitioning, and move low-frequency librdkafka settings
behind internal defaults.

## Scope

This design covers:

- `src/output-eve-kafka.c`
- `src/output-eve-kafka.h`
- Kafka example configuration in `suricata.yaml.in`
- Kafka EVE output C unit tests in `src/output-eve-kafka.c`

It does not change Kafka security support, topic names, broker configuration,
queue ownership, delivery statistics, or the producer thread model.

## Design Goals

- Prevent fixed-partition misconfiguration from causing `Unknown partition`
  delivery failures.
- Keep the user-facing Kafka configuration focused on common operational needs.
- Preserve production-oriented librdkafka defaults in code.
- Keep topic auto-creation configurable, with a default of 3 partitions for new
  topics.
- Avoid changing SSL, SASL, compression, acknowledgment, or Suricata queue
  sizing behavior.

## User-Facing Configuration

Keep these Kafka EVE output options:

- `brokers`
- `topic`
- `client-id`
- `topic-auto-create`
- `topic-partitions`
- `compression`
- `acks`
- `ring-buffer-size`
- `ring-buffer-max-bytes`
- `max-drain-batch`
- `idle-poll-ms`
- `security-protocol`
- `ssl-ca-location`
- `ssl-certificate-location`
- `ssl-key-location`
- `ssl-key-password`
- `sasl-mechanism`
- `sasl-username`
- `sasl-password`

Remove these user-facing options:

- `partition`
- `queue-buffering-max-messages`
- `queue-buffering-max-kbytes`
- `message-timeout-ms`
- `socket-timeout-ms`
- `metadata-max-age-ms`
- `retry-backoff-ms`
- `retry-backoff-max-ms`
- `reconnect-backoff-ms`
- `reconnect-backoff-max-ms`
- `linger-ms`

`topic-partitions` remains user configurable because it controls a visible
administrative action when `topic-auto-create: yes` is enabled. Its default
should be 3 in both code and `suricata.yaml.in`.

## Internal Defaults

The removed librdkafka tuning options should remain as internal defaults:

- `queue.buffering.max.messages`: `100000`
- `queue.buffering.max.kbytes`: `131072`
- `message.timeout.ms`: `300000`
- `socket.timeout.ms`: `30000`
- `metadata.max.age.ms`: `300000`
- `retry.backoff.ms`: `100`
- `retry.backoff.max.ms`: `1000`
- `reconnect.backoff.ms`: `100`
- `reconnect.backoff.max.ms`: `10000`
- `linger.ms`: `5`

These values are already present in the implementation and are reasonable
general-purpose producer settings. They should be applied in
`KafkaCreateRdKafkaConf()` from constants, not from fields parsed out of
`KafkaSetup`.

## Produce Path

The Kafka output should always use librdkafka automatic partitioning.

`KafkaSetup` should no longer store a `partition` field. The drain and produce
helpers should stop accepting a partition argument unless a test seam still
needs to observe the effective partition value. The final `rd_kafka_producev()`
call should use:

```c
RD_KAFKA_V_PARTITION(RD_KAFKA_PARTITION_UA)
```

This preserves Kafka's default partitioning behavior and removes the user path
that can point messages at a nonexistent topic partition.

## Config Parsing

`KafkaParseConfig()` should stop reading the removed options. It should still
parse and validate retained numeric options:

- `topic-partitions`, minimum `1`
- `ring-buffer-size`, minimum `2`
- `ring-buffer-max-bytes`, minimum `1`
- `max-drain-batch`, minimum `1`
- `idle-poll-ms`, minimum `1`

The retry and reconnect ordering checks become unnecessary because those values
are no longer user configurable.

Unknown removed options should not need a special compatibility warning in this
change unless the existing configuration system already reports unknown keys
for this subtree. The example YAML should no longer advertise them.

## Documentation and Examples

`suricata.yaml.in` should show only the retained Kafka options. The Kafka
example should state:

- `topic-partitions: 3`
- The setting applies only to auto-created topics.
- Message partitioning is automatic.

The removed librdkafka tuning block should be deleted from the example to keep
the operational configuration short.

## Tests

Remove tests that validate deleted configuration:

- invalid `partition`
- retry backoff ordering
- reconnect backoff ordering
- retry backoff zero override
- configured partition usage in the drain path

Adjust or add tests for retained behavior:

- default `topic_partitions` is 3
- configured `topic-partitions` still overrides the default
- invalid `topic-partitions: 0` still fails
- drain/produce path uses `RD_KAFKA_PARTITION_UA`

The test changes should stay in `src/output-eve-kafka.c` with the existing
`UNITTESTS` structure.

## Migration Impact

Deployments that currently set `partition` will no longer be able to force all
messages to a single Kafka partition. Messages will be distributed according to
librdkafka's automatic partitioning behavior.

Deployments that currently set the removed low-frequency librdkafka options
will use Suricata's internal defaults instead. The retained queue sizing
options still provide the primary Suricata-side memory and throughput controls.

This is an intentional simplification that favors a smaller and safer
configuration surface over exposing every producer tuning knob.
