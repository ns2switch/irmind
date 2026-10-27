# Evidence graph benchmark

This page is for maintainers measuring the local DuckDB graph. It records the method and results for the [manual and weekly workflow](../../.github/workflows/graph-benchmark.yml). The workflow uses synthetic data only and is never part of a pull request check.

## Method

The ignored `graph_benchmark_1gb` test ingests 25 distinct CloudTrail JSON files of just over 40 MiB each through the signed case use case. The total exceeds 1,000,000,000 input bytes. One file is built and ingested at a time; the temporary case directory is removed when the test ends. The query searches the indexed event name and returns at most 20 records.

The test measures wall-clock ingestion and query time. Token counts are estimates of bytes divided by four, so they are useful only for comparing the raw input with this query response. They are not provider billing counts. The graph is derived from signed evidence, and the full-text term index is checked during graph verification.

## Results

| Date and revision | Environment | Input bytes | Ingestion | Query | Raw tokens, estimated | Indexed response tokens, estimated |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 2026-10-27, `70fc844` | Local Linux, one process, 6 GB address-space cap, no swap | 1,048,578,740 | 1,274.926 s | 1.369 s | 262,144,685 | 583 |
| 2026-10-27, C4 Appender working tree | Same machine, dataset, test profile, and limits | 1,048,578,740 | 1,250.558 s | 0.790 s | 262,144,685 | 583 |

The Appender change improved end-to-end ingestion by 1.02x and this query by 1.73x. It did not reach the indicative 10x ingestion target. Each input file contains one 40 MiB record, so this benchmark exercises large-record handling more than batched row insertion. The measurement includes custody verification before each file, evidence writes, content screening, parsing, and DuckDB indexing. Repeated verification of prior evidence dominates the end-to-end path. A separate 40 MiB profiling run measured 6.260 s in content screening and 2.667 s in graph indexing; it does not substitute for the 1 GB comparison. The query returns at most 20 of the 25 synthetic records. Both temporary case directories were removed.

The scheduled workflow will publish its own log as an artifact. GitHub cannot dispatch a newly added workflow from a pull request branch before the workflow exists on `main`; its first CI measurement is therefore pending the merge. Do not extrapolate a smaller run into this table or treat these estimated tokens as a provider bill.
