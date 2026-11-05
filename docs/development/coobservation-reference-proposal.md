# Co-observation event references

This proposal is for maintainers evaluating the disk/query trade-off of a future co-observation schema. It does not change the approved V2 artifact or any signed bytes.

## Current representation

Every co-observation already identifies its event with `source_hash` and `record_index`. The precise schema also repeats `event_time`, `submicro_nanos`, `time_precision`, `time_inferred` and `source_offset`. Event artifacts retain those fields independently. Keeping them in co-observations allows direct time filtering during bounded neighbor and path queries.

## Measure before changing the schema

The release benchmark reports compressed column payload by artifact family:

- `PARQUET_COOBS_COLUMN`: compressed bytes for each column in the active co-observation inventory.
- `PARQUET_COOBS_BUDGET`: active co-observation file bytes and the sum of the five repeated time/order columns.

These are measurements of the existing signed artifacts. They are not a claimed size for a redesigned file: footer metadata would also change, and an event-reference lookup could require additional IO. Here, the lineage-active storage inventory includes retained compaction inputs and their replacement bundles. Query selection can read only the replacement bundles, so this is a storage budget, not a query-scan footprint. Retired migration generations are excluded from this inventory. The benchmark also records total on-disk co-observation storage.

The paired release matrix covers the full 15 GB cloud, chronological endpoint and disordered endpoint corpora, including 1, 64, 1,024 and 1,025 hosts. Column totals separate the four repeated time/precision fields from `source_offset`, which is an additional order field. These payload sums bound the potential saving; they do not measure a rewritten file or a reference join.

## Measured payload budget

The [paired standard-runner release matrix](https://github.com/ns2switch/irmind/actions/runs/42090681509) includes the unchanged writer on both sides of the entity-query comparison. The storage counters are identical within every pair. The [structured measurements](benchmarks/v2-coobservation-budget.json) identify both frozen revisions and archive checksums. All sizes below are decimal; time/precision means the four fields excluding `source_offset`.

| 15 GB V2 workload | Co-observation storage GB | Repeated time/precision MB | Payload share | Extra offset MB |
| --- | ---: | ---: | ---: | ---: |
| cloud-v2 | 5.960 | 33.125 | 0.556% | 8.096 |
| endpoint-v2-1 | 1.249 | 159.283 | 12.751% | 5.668 |
| endpoint-v2-1-chronological | 1.798 | 708.893 | 39.421% | 5.668 |
| endpoint-v2-1024 | 1.224 | 155.426 | 12.700% | 5.562 |
| endpoint-v2-1024-chronological | 1.762 | 694.544 | 39.410% | 5.562 |
| endpoint-v2-1025 | 1.224 | 155.479 | 12.698% | 5.565 |
| endpoint-v2-1025-chronological | 1.763 | 694.891 | 39.409% | 5.565 |
| endpoint-v2-64 | 1.249 | 159.283 | 12.754% | 5.668 |
| endpoint-v2-64-chronological | 1.798 | 708.893 | 39.425% | 5.668 |

Chronological endpoint times have greater cardinality than the repeated-slab disorder control, so their compressed time payload is much larger. Removing those four repeated fields could avoid about 709 MB of column payload per chronological case, compared with 155–159 MB in the disordered cases and 33 MB in cloud. Removing the offset as well adds only about 6–8 MB. The existing cloud `co_entities` payload is roughly 4.04 GB, so event-time deduplication does not address its main disk cost.

Recommendation: evaluate a separately versioned reference-only co-observation schema for endpoint storage, with the reference-resolution design below. Keep the current schema in this optimization stack. Do not claim the payload budget as an achieved file saving or assume that extra authenticated event reads preserve the neighbor/path latency target. A follow-up must write the alternative, measure its full files and joins, and pass reconstruction, cancellation and bounded-query tests before changing production artifacts.

## Candidate design if the saving warrants it

Keep `(source_hash, record_index)` as the event reference. Remove repeated time/order columns only from a newly versioned co-observation schema, never by reinterpreting the existing schema label. Retain compatible readers and deterministic reconstruction for the old schema. Record any new builder/schema identity explicitly in the signed artifact envelope.

For a time-constrained neighbor or path query, resolve matching event references from authenticated event artifacts before using co-observations. Keep all existing sample, expansion, result and time budgets. Report partial or truncated results exactly as today. Hash-verify both artifact families before reading and validate every reference against the signed source set.

A schema change requires a separate design decision, new golden fixtures and explicit approval. It must demonstrate the measured disk saving and the effect on query p50/p95, cold reads and cancellation. This measurement change does not implement that design.

See [issue #37](https://github.com/ns2switch/irmind/issues/37) for the broader disk-size and query work, and [the benchmark results](benchmarks.md#timestamp-and-host-partition-comparison) for the current baseline.
