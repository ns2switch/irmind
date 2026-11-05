# Co-observation event references

This proposal is for maintainers evaluating the disk/query trade-off of a future co-observation schema. It does not change the approved V2 artifact or any signed bytes.

## Current representation

Every co-observation already identifies its event with `source_hash` and `record_index`. The precise schema also repeats `event_time`, `submicro_nanos`, `time_precision`, `time_inferred` and `source_offset`. Event artifacts retain those fields independently. Keeping them in co-observations allows direct time filtering during bounded neighbor and path queries.

## Measure before changing the schema

The release benchmark reports compressed column payload by artifact family:

- `PARQUET_COOBS_COLUMN`: compressed bytes for each column in the active co-observation inventory.
- `PARQUET_COOBS_BUDGET`: active co-observation file bytes and the sum of the five repeated time/order columns.

These are measurements of the existing signed artifacts. They are not a claimed size for a redesigned file: footer metadata would also change, and an event-reference lookup could require additional IO. Retained historical generations are separate from the active-file budget. The benchmark still records total on-disk co-observation storage.

Collect the full 15 GB cloud, chronological endpoint and disordered endpoint results, including 1, 64, 1,024 and 1,025 hosts. Report the repeated-column share alongside total disk size before deciding whether the saving justifies extra query work.

## Candidate design if the saving warrants it

Keep `(source_hash, record_index)` as the event reference. Remove repeated time/order columns only from a newly versioned co-observation schema, never by reinterpreting the existing schema label. Retain compatible readers and deterministic reconstruction for the old schema. Record any new builder/schema identity explicitly in the signed artifact envelope.

For a time-constrained neighbor or path query, resolve matching event references from authenticated event artifacts before using co-observations. Keep all existing sample, expansion, result and time budgets. Report partial or truncated results exactly as today. Hash-verify both artifact families before reading and validate every reference against the signed source set.

A schema change requires a separate design decision, new golden fixtures and explicit approval. It must demonstrate the measured disk saving and the effect on query p50/p95, cold reads and cancellation. This measurement change does not implement that design.

See [issue #37](https://github.com/ns2switch/irmind/issues/37) for the broader disk-size and query work, and [the benchmark results](benchmarks.md#timestamp-and-host-partition-comparison) for the current baseline.
