# Evidence graph benchmarks

This page is for maintainers measuring local graph ingestion and queries. The [manual and weekly workflow](../../.github/workflows/graph-benchmark.yml) runs synthetic 1 GB and 15 GB Parquet benchmarks and uploads the results as an artifact. The older DuckDB graph baseline is optional in manual runs. These benchmarks do not run on pull requests.

## Corpora and method

The representative corpus contains 1,000 CloudTrail-shaped files of approximately 1 MiB each. Each file has hundreds of 1–2 KiB JSON records with synthetic identities, requests, response metadata, TLS details, and reserved example IP addresses. Request IDs vary across files. The separate extreme corpus contains 25 files with one approximately 40 MiB JSON record each. Both exceed 1,000,000,000 input bytes.

Each test creates a new case and ingests every file through the normal signed use case. The profile separates reading and hashing, custody verification, guard screening, JSON parsing, entity extraction, DuckDB insertion, evidence writes, audit writes, and the bounded text query. The representative query searches a selective synthetic request ID; the extreme query searches the event name. The original files, stored evidence, and derived graph all live in a temporary directory that the test removes on completion. The benchmark records input and returned tokens as bytes divided by four. These are comparison estimates, not provider billing counts.

## Results

The previous C4 benchmark measured the extreme corpus only. Its single 40 MiB record per file made it a poor proxy for normal CloudTrail ingestion.

| Revision | Environment | Corpus | Input bytes | Ingest | Query | Raw tokens, estimated | Returned tokens, estimated |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| C4 before Appender, `70fc844` | Local Linux, 6 GB address-space cap, test profile, no swap | Extreme | 1,048,578,740 | 1,274.926 s | 1.369 s | 262,144,685 | 583 |
| C4 Appender working tree | Same machine, corpus, profile, and cap | Extreme | 1,048,578,740 | 1,250.558 s | 0.790 s | 262,144,685 | 583 |

The C4b measurements below use the same local Linux machine and test profile, with an 8 GB address-space cap and no swap. The first complete representative result is the baseline for future releases; no full-size representative result exists from C4.

| Revision | Corpus | Input bytes | Files | Ingest | Query | Raw tokens, estimated | Returned tokens, estimated |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| C4b, 2026-10-28 | Representative CloudTrail | 1,045,737,000 | 1,000 | 980.910 s | 0.470 s | 261,434,250 | 39 |
| C4b, 2026-10-28 | Extreme large record | 1,048,578,740 | 25 | 188.033 s | 0.701 s | 262,144,685 | 583 |
| C4b Arrow term batches, 2026-10-28 | Representative CloudTrail | 1,045,737,000 | 1,000 | 792.161 s | 0.506 s | 261,434,250 | 39 |
| C4b Arrow term batches, [GitHub Linux runner](https://github.com/ns2switch/irmind/actions/runs/40690758301) | Representative CloudTrail | 1,045,737,000 | 1,000 | 1,341.574 s | 2.604 s | 261,434,250 | 39 |
| C4b Arrow term batches, [GitHub Linux runner](https://github.com/ns2switch/irmind/actions/runs/40690758301) | Extreme large record | 1,048,578,740 | 25 | 219.729 s | 1.689 s | 262,144,685 | 583 |

### Phase profile

Percentages use ingestion plus query time as the denominator. Guard time covers the bounded query result. The original evidence is stored without screening; text is screened before model or terminal display. DuckDB insertion includes Appender calls and transaction commits. A full `verify` remains available and is not replaced by the incremental ingestion checkpoint.

| Corpus | Phase | Seconds | Percent |
| --- | --- | ---: | ---: |
| Representative | Read and hash | 42.144 | 4.3% |
| Representative | Custody verification | 61.138 | 6.2% |
| Representative | Guard | 0.001 | 0.0% |
| Representative | JSON parse | 16.028 | 1.6% |
| Representative | Entity extraction | 43.197 | 4.4% |
| Representative | DuckDB insertion | 699.963 | 71.3% |
| Representative | Evidence write | 67.430 | 6.9% |
| Representative | Audit write | 50.872 | 5.2% |
| Representative | Query | 0.470 | 0.0% |
| Representative | Other | 0.138 | 0.0% |
| Representative, Arrow batches | Read and hash | 41.634 | 5.3% |
| Representative, Arrow batches | Custody verification | 60.956 | 7.7% |
| Representative, Arrow batches | Guard | 0.001 | 0.0% |
| Representative, Arrow batches | JSON parse | 15.985 | 2.0% |
| Representative, Arrow batches | Entity extraction | 43.589 | 5.5% |
| Representative, Arrow batches | DuckDB insertion | 531.054 | 67.0% |
| Representative, Arrow batches | Evidence write | 58.501 | 7.4% |
| Representative, Arrow batches | Audit write | 40.294 | 5.1% |
| Representative, Arrow batches | Query | 0.506 | 0.1% |
| Representative, Arrow batches | Other | 0.148 | 0.0% |
| Extreme | Read and hash | 41.637 | 22.1% |
| Extreme | Custody verification | 40.590 | 21.5% |
| Extreme | Guard | 0.003 | 0.0% |
| Extreme | JSON parse | 2.513 | 1.3% |
| Extreme | Entity extraction | 17.090 | 9.1% |
| Extreme | DuckDB insertion | 49.875 | 26.4% |
| Extreme | Evidence write | 25.994 | 13.8% |
| Extreme | Audit write | 10.328 | 5.5% |
| Extreme | Query | 0.701 | 0.4% |
| Extreme | Other | 0.007 | 0.0% |

The manual GitHub Linux run used the same `ci` profile and synthetic corpus as the local run. Its phase profile was:

| Phase | Representative seconds | Representative share | Extreme seconds | Extreme share |
| --- | ---: | ---: | ---: | ---: |
| Read and hash | 57.840 | 4.3% | 58.396 | 26.4% |
| Custody verification | 87.879 | 6.5% | 57.367 | 25.9% |
| Guard | 0.002 | 0.0% | 0.005 | 0.0% |
| JSON parse | 26.883 | 2.0% | 4.566 | 2.1% |
| Entity extraction | 75.523 | 5.6% | 28.486 | 12.9% |
| DuckDB insertion | 1,062.501 | 79.0% | 41.483 | 18.7% |
| Evidence write | 29.561 | 2.2% | 29.343 | 13.3% |
| Audit write | 1.213 | 0.1% | 0.030 | 0.0% |
| Query | 2.604 | 0.2% | 1.689 | 0.8% |
| Other | 0.174 | 0.0% | 0.059 | 0.0% |

Within the representative DuckDB insertion, commits took 378.418 s, text-term Appender writes 171.678 s, and node aggregation 102.414 s. This measured cost prevents the indicative two-minute target locally. The two complete tests took 1,222.01 s together, including corpus generation and temporary cleanup; `ingest_seconds` excludes those costs. The extreme ingestion improved by 6.7x from the C4 Appender measurement on the same machine. Neither corpus met two minutes locally.

The parser phase was small in local samples, so files remain in deterministic serial order. Parsing files in parallel would not address the measured DuckDB and storage costs. The 256 MiB DuckDB WAL checkpoint threshold reduces repeated small checkpoints while preserving committed writes and crash recovery; [DuckDB documents the setting](https://duckdb.org/docs/lts/configuration/overview).

Arrow record batches cut local representative ingestion by 188.749 s (19.2%) on the same machine. DuckDB insertion fell by 168.909 s (24.1%): term writes fell from 171.678 to 128.957 s, and commits from 378.418 to 226.022 s. The per-file finish phase, including node aggregation, took 118.254 s after the change. Secondary indexes are absent during bulk loading and built on the first query that needs them; text search, graph summary, and record checks do not build unrelated indexes. The first text query remained near the baseline at 0.506 s versus 0.470 s. The 792.161 s ingestion remains 6.6 times above the indicative two-minute target locally. Even with DuckDB insertion eliminated, read/hash, custody, parsing, extraction, evidence writes, and audit writes would total 260.959 s on this machine; the target therefore cannot be met here by changing the term index alone.

The runner's representative DuckDB phase split into 218.715 s of term writes, 382.680 s of per-file finish work, and 373.817 s of commits. Its non-DuckDB ingestion phases alone totaled 278.899 s. The representative result is 11.2 times the indicative two-minute target on this runner; changing the term writer alone cannot meet that target. There is no pre-change run on the same GitHub runner, so the 19.2% before/after comparison above is local only. Reaching two minutes requires a broader design change that reduces both per-file graph transactions and the non-graph custody and evidence I/O while preserving their guarantees.

The target of less than two minutes on a standard GitHub runner is indicative. The linked manual run and its artifact are the runner measurement.
These are single runs under an 8 GB address-space cap with no swap; filesystem cache and other host activity can affect the comparison.

## Partitioned Parquet

The new benchmark creates 1,000 CloudTrail-shaped files of about 1 MB each, signs source and artifact manifests, and compacts same-partition Parquet files into signed bundles. It deletes each four-file source batch immediately after conversion. The 15 GB variant repeats each file's synthetic records 15 times and also avoids keeping the full input corpus on disk. Both variants measure source hashing, conversion, compressed disk size, and five bounded DuckDB queries. They run in the release profile in the manual and weekly workflow, not in PR checks. The local diagnostics below used the unoptimized test profile and are not a substitute for the standard-runner result.

The first two local 1 GB runs used the same Linux machine, unoptimized test profile, no swap, and the same 1,045,717,000 input bytes. The second run includes a per-case authenticated artifact catalog; the first query still validates the whole chain. It does **not** replace explicit full verification.

| Local revision | Ingest wall time | Hash CPU sum | Conversion CPU sum | Parquet write CPU sum | Parquet disk bytes | First query |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Signed bundles, no catalog cache | 233.367 s | 21.758 s | 285.343 s | 103.016 s | 301,200,871 | 26.724 s term p95 |
| Signed bundles, catalog cache | 246.755 s | 22.024 s | 286.021 s | 98.286 s | 301,200,871 | 24.710 s summary |

The CPU sums overlap because four source files can be prepared in parallel. Host activity varied between runs, so the 13.388 s ingest difference is not evidence of a regression. The Parquet disk figure includes the signed single-source files retained for reconstruction and the active compact bundles. It is about 28.8% of the input size.

| Warm 1 GB query | p50 | p95 | Errors |
| --- | ---: | ---: | ---: |
| Term | 4.138 s | 4.161 s | 0 |
| Entity lookup | 0.653 s | 0.667 s | 0 |
| Neighbors | 3.449 s | 3.483 s | 0 |
| Timeline | 2.567 s | 2.571 s | 0 |
| Direct path | 0.890 s | 0.908 s | 0 |

Before the catalog cache, warm queries still spent 23–27 s each: around 21 s was repeated audit-chain validation, while Parquet hashing and SQL accounted for about 1.25 s and 1.10 s per query on average. The cache checks the signed head and SQLite `data_version`, and a test alters an earlier entry from another connection to ensure that change invalidates it. Each selected Parquet file is still hashed before DuckDB reads it.

These local measurements preceded the signed catalog and compaction changes below. They do not measure the final large-case path.

### Standard-runner Parquet result

The [manual Linux run on the Phase P branch](https://github.com/ns2switch/irmind/actions/runs/40765451457) completed all three synthetic Parquet tests in the release profile. It generated each four-file batch on the runner, ingested it through the signed use case, and deleted that temporary batch. The 15 GB result measures conversion and custody on this runner; it does not include cloud transfer or reading a persistent 15 GB source tree. The workflow artifact contains the raw benchmark output.

| Corpus | Input bytes | Files | Ingest wall time | Source hash CPU sum | Conversion CPU sum | Record conversion CPU sum | Parquet write CPU sum | Parquet disk bytes | Cold summary |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Representative 1 GB | 1,045,717,000 | 1,000 | 26.982 s | 1.344 s | 51.181 s | 8.759 s | 9.412 s | 301,108,413 | 0.293 s |
| Representative 15 GB | 15,685,573,000 | 1,000 | 243.944 s | 17.955 s | 711.098 s | 132.677 s | 85.295 s | 1,803,559,114 | 0.988 s |

The CPU sums overlap across four parallel source workers; they must not be added to infer wall time. The Parquet disk figures include signed single-source artifacts retained for reconstruction and active compact bundles. They are 28.8% and 11.5% of the respective input sizes. The lower 15 GB ratio reflects repeated synthetic records; it is not a compression forecast for real cases. The timed 15 GB ingestion is 4.07 minutes, below the 15-minute target.

| Query | 1 GB p50 | 1 GB p95 | 15 GB p50 | 15 GB p95 | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| Term search | 1.001 s | 1.007 s | 7.631 s | 7.650 s | 0 |
| Entity lookup | 0.129 s | 0.129 s | 1.339 s | 1.400 s | 0 |
| Neighbors | 0.074 s | 0.078 s | 0.454 s | 0.462 s | 0 |
| Timeline | 0.155 s | 0.157 s | 1.034 s | 1.034 s | 0 |
| Direct path | 0.206 s | 0.212 s | 2.461 s | 2.470 s | 0 |

Each p50/p95 uses five warm calls after a cold summary. Across those 26 calls, 15 GB artifact verification took 10.244 s and DuckDB SQL took 53.147 s. Every measured p95 is below 10 seconds. Neighbor search samples at most 4,096 matching records and marks a truncated result as partial. The measured path connects entities in one record; the final path implementation also searches up to three hops with a 10-second budget and labels exhausted searches as truncated. That worst-case multi-hop path was not part of this benchmark. The same workflow also ran a 50 MB diagnostic successfully.
