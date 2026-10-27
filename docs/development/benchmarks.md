# Evidence graph benchmark

This page is for maintainers measuring the local DuckDB graph. It records the method and results for the [manual and weekly workflow](../../.github/workflows/graph-benchmark.yml). The workflow uses synthetic data only and is never part of a pull request check.

## Method

The ignored `graph_benchmark_1gb` test ingests 25 distinct CloudTrail JSON files of just over 40 MiB each through the signed case use case. The total exceeds 1,000,000,000 input bytes. One file is built and ingested at a time; the temporary case directory is removed when the test ends. The query searches the indexed event name and returns at most 20 records.

The test measures wall-clock ingestion and query time. Token counts are estimates of bytes divided by four, so they are useful only for comparing the raw input with this query response. They are not provider billing counts. The graph is derived from signed evidence, and the full-text term index is checked during graph verification.

## Results

The first 1 GB run must be recorded here from the workflow artifact before H7 is marked complete. Record the commit, runner, input bytes, ingestion time, query time, estimated raw tokens, and estimated indexed-result tokens. Do not extrapolate a smaller run into this table.
