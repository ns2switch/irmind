# Evidence scan benchmarks

This page is for maintainers comparing signed Parquet ingestion and bounded evidence queries. The [manual and weekly workflow](../../.github/workflows/graph-benchmark.yml) generates synthetic 1 GB and 15 GB corpora on a standard Linux runner. It uploads the raw output. No corpus or original evidence is kept as an artifact.

## Method

The representative CloudTrail-shaped corpus has about 1,000 files of approximately 1 MB, each with 1–2 KB records. The 15 GB variant repeats synthetic records within those files and deletes each temporary source batch after conversion. A separate extreme corpus has 25 files with one large record per file; its historical result is kept only as a stress reference. Every case uses the signed source manifest and signed Parquet artifact path. Each query verifies the selected Parquet files by SHA-256 before reading. The benchmark runs in the release profile, takes five warm samples per query after a cold summary, and reports p50/p95. Times are wall-clock unless marked as CPU sums. Files are removed after each run.

| Revision | Input | Ingest | Parquet disk | Cold summary |
| --- | ---: | ---: | ---: | ---: |
| Previous SQL reader, [same-workflow baseline](https://github.com/ns2switch/irmind/actions/runs/41128581228) | 1,045,717,000 B | 28.145 s | 301,108,413 B | 0.297 s |
| Previous SQL reader, [same-workflow baseline](https://github.com/ns2switch/irmind/actions/runs/41128581228) | 15,685,573,000 B | 264.693 s | 1,803,559,114 B | 0.947 s |

The previous reader's 15 GB ingestion met the 15-minute target. The corpus repeats synthetic records, so its compression ratio is not a forecast for real evidence. The CPU phase sums overlap across four source workers.

| Previous SQL reader, warm query | 1 GB p50 | 1 GB p95 | 15 GB p50 | 15 GB p95 |
| --- | ---: | ---: | ---: | ---: |
| Term search | 1.036 s | 1.039 s | 7.911 s | 7.925 s |
| Entity lookup | 0.149 s | 0.150 s | 1.495 s | 1.603 s |
| Neighbors | 0.077 s | 0.084 s | 0.467 s | 0.477 s |
| Timeline | 0.157 s | 0.159 s | 1.053 s | 1.056 s |
| Direct path | 0.086 s | 0.089 s | 0.460 s | 0.470 s |

The direct path sample connects entities in one record. The path implementation also allows three hops, 200 expansions, 50 neighbors per entity, and a 10-second budget; that worst case was not part of the benchmark. Neighbors samples at most 4,096 matching records and labels partial results. These limits are preserved by the direct reader.

## Direct Arrow/Parquet reader

The new reader prunes signed partitions, projects required columns, uses row-group statistics and row filters where possible, and streams batches with bounded channels. It hashes each selected artifact on the same file handle before parsing it. Four standard-library workers read independent files while the caller receives batches in deterministic manifest order. The 10-second query budget includes hash verification. No SQL engine or text-term index is loaded.

The before/after runner measurements for the direct reader are being generated in the [same benchmark workflow](../../.github/workflows/graph-benchmark.yml). The PR must report ingestion, p50/p95 for every query, cold and warm compile time, binary size, and any query regression above 25% before it is ready for review.
