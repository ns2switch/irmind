# Evidence scan benchmarks

This page is for maintainers comparing signed Parquet ingestion and bounded evidence queries. The [manual and weekly workflow](../../.github/workflows/graph-benchmark.yml) generates synthetic 1 GB and 15 GB corpora on a standard Linux runner. It uploads the raw output. No corpus or original evidence is kept as an artifact.

## Method

The representative CloudTrail-shaped corpus has about 1,000 files of approximately 1 MB, each with 1–2 KB records. The 15 GB variant repeats synthetic records within those files and deletes each temporary source batch after conversion. A separate extreme corpus has 25 files with one large record per file; its historical result is kept only as a stress reference. Every case uses the signed source manifest and signed Parquet artifact path. Each query verifies the selected Parquet files by SHA-256 before reading. The benchmark runs in the release profile, takes five warm samples per query after a cold summary, and reports p50/p95. Times are wall-clock unless marked as CPU sums. Files are removed after each run.

| Revision | Input | Ingest | Parquet disk | Cold summary |
| --- | ---: | ---: | ---: | ---: |
| Previous SQL reader, [same-workflow baseline](https://github.com/ns2switch/irmind/actions/runs/41128581228) | 1,045,717,000 B | 28.145 s | 301,108,413 B | 0.297 s |
| Previous SQL reader, [same-workflow baseline](https://github.com/ns2switch/irmind/actions/runs/41128581228) | 15,685,573,000 B | 264.693 s | 1,803,559,114 B | 0.947 s |
| Direct reader, [measured run](https://github.com/ns2switch/irmind/actions/runs/41138351183) | 1,045,717,000 B | 29.104 s | 301,108,413 B | 0.220 s |
| Direct reader, [measured run](https://github.com/ns2switch/irmind/actions/runs/41138351183) | 15,685,573,000 B | 266.277 s | 1,803,559,114 B | 0.665 s |

Both readers met the 15-minute ingestion target. The direct reader took 0.6% longer at 15 GB. The corpus repeats synthetic records, so its compression ratio is not a forecast for real evidence. The phase sums overlap across four source workers and must not be added to estimate wall time.

| Reader and input | Hash | Conversion | Row preparation | Parquet write | Wall |
| --- | ---: | ---: | ---: | ---: | ---: |
| Previous, 1 GB | 0.958 s | 56.474 s | 9.817 s | 8.477 s | 28.145 s |
| Direct, 1 GB | 1.462 s | 55.270 s | 9.386 s | 11.372 s | 29.104 s |
| Previous, 15 GB | 11.697 s | 800.591 s | 148.470 s | 84.359 s | 264.693 s |
| Direct, 15 GB | 18.959 s | 753.325 s | 139.122 s | 93.463 s | 266.277 s |

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

The direct-reader results below come from the [same standard-runner workflow](https://github.com/ns2switch/irmind/actions/runs/41138351183). All measured 15 GB p95 values stayed below 10 seconds. A first direct-reader run used a byte-by-byte case-insensitive substring scan; it exceeded the deadline at 12.346 seconds. Searching candidate final bytes with `memchr` reduced term-search p95 to 3.813 seconds without changing matching semantics.

| Direct reader, warm query | 1 GB p50 | 1 GB p95 | 15 GB p50 | 15 GB p95 |
| --- | ---: | ---: | ---: | ---: |
| Term search | 0.343 s | 0.352 s | 3.779 s | 3.813 s |
| Entity lookup | 0.180 s | 0.190 s | 2.570 s | 2.632 s |
| Neighbors | 0.590 s | 0.594 s | 8.213 s | 8.550 s |
| Timeline | 0.221 s | 0.223 s | 2.882 s | 2.886 s |
| Direct path | 0.580 s | 0.615 s | 8.269 s | 8.554 s |

At 15 GB, entity lookup is 64% slower, timeline 173% slower, neighbors 1,692% slower, and path 1,720% slower than the previous SQL reader. These operations scan entity Parquet row groups; neighbors and path also scan co-observed records a second time. The direct reader trades a material graph-query slowdown for a smaller, faster build. A follow-up should add entity-value Bloom filters to row groups and a bounded, partitioned co-observation artifact; it should also use borrowed record keys to avoid allocating a string for each scanned entity. Those optimizations must retain signed artifact hashes, bounded memory, and the current partial-result labels. Until then, analysts should narrow large cases by date, account or project, and region. The 10-second target is measured for this synthetic 15 GB workload, not promised for an unfiltered 500 GB query.

| Build or package measurement | Previous reader | Direct reader |
| --- | ---: | ---: |
| Cold release test build, same workflow | 42m 11s | 8m 06s |
| Warm release test build | Not measured | 21 s |
| Additional full release binary build after test build | Not measured | 15m 36s |
| Release binary size | 104,377,128 B | 44,074,000 B |
| Packages in Cargo.lock | 576 | 536 |

The previous binary size is from the [last main build with the former reader](https://github.com/ns2switch/irmind/actions/runs/41038459252). Release test builds are directly comparable; the binary build is a separate measurement and must not be added to the test-build row as if it were a warm rebuild. The new binary is 57.8% smaller. The previous Linux `main` job took 3m 58s with a warm cache; this PR's Linux job took 13m 02s after the lockfile changed. A matched warm Linux run on `main` cannot be measured before this PR merges. The cold release build is the reliable same-workflow compilation comparison. No extra CI run was started just to fill that gap.

## HuntEval normalized episodes

The manual and weekly benchmark fetches [HuntEval](https://github.com/ns2switch/HuntEval) commit `4cbb555a56bc17cb03b988ad2f15b1374eecf183` and verifies the SHA-256 of all 18 public `source/events.json` files and 18 private `ground-truth.json` files against [`scripts/hunteval.sha256`](../../scripts/hunteval.sha256). The parser ingests only the public JSON, never HuntEval's Parquet or hidden answers. The evaluator reads the answers separately. One public AWS episode is versioned as an attributed parser fixture.

The model-free check asserts that `entity_lookup`, term search, entity timeline, neighbors, and path recover every malicious event and entity specified by each episode. It also checks the attack-event order and reports parser errors. The local baseline below used debug builds and temporary cases; it is a functional check, not a standard-runner latency claim.

| Local corpus | AWS events / entities / path | Azure events / entities / path | GCP events / entities / path | Parser errors |
| --- | --- | --- | --- | ---: |
| 18 isolated episodes | 19/19 · 10/10 · 14/14 | 19/19 · 10/10 · 14/14 | 19/19 · 10/10 · 14/14 | 0 |
| 50 MB synthetic noise plus all 18 episodes | 19/19 · 10/10 · 14/14 | 19/19 · 10/10 · 14/14 | 19/19 · 10/10 · 14/14 | 0 |

The 1 GB and 15 GB standard-runner needle measurements are collected by the [manual and weekly benchmark workflow](../../.github/workflows/graph-benchmark.yml). Its synthetic noise uses account `999900001111` and IP `198.18.254.42`, which do not occur in the pinned HuntEval corpus. The episode files remain unchanged and are added before Parquet compaction. The [pinned baseline run](https://github.com/ns2switch/irmind/actions/runs/41190348193) passed both corpora; its raw output is attached to that run. These times are from the same runner class as the earlier direct-reader measurements, not a guarantee that GitHub assigned the same physical host.

| Baseline corpus | Ingest | Parquet disk | Term p95 | Entity p95 | Neighbors p95 | Timeline p95 | Path p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 GB plus 18 episodes | 25.816 s | 301,259,285 B | 0.292 s | 0.160 s | 0.600 s | 0.197 s | 0.579 s |
| 15 GB plus 18 episodes | 229.378 s | 1,803,662,772 B | 3.162 s | 2.306 s | 8.093 s | 2.650 s | 8.190 s |

| 15 GB provider | Malicious events | Malicious entities | Attack-path segments | Parse errors | Maximum query p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| AWS | 19/19 | 10/10 | 14/14 | 0 | 0.002 s |
| Azure | 19/19 | 10/10 | 14/14 | 0 | 0.002 s |
| GCP | 19/19 | 10/10 | 14/14 | 0 | 0.002 s |

The needle queries use the episode's observed UTC window and provider, so partition pruning excludes the unrelated noise. The generic query samples above intentionally use a common entity across the synthetic corpus and show the broad-query cost. The run also measured an 8-second warm release test rebuild and a 44,145,224-byte release binary; neither is an ingestion latency.

The first 15 GB run exposed the unfiltered reader's 10-second path budget: one attack-path lookup returned its explicit truncated result. The evaluator now supplies the episode's observed UTC window and provider as normal graph filters, so signed partition pruning narrows each query without raising the budget or bypassing artifact hash verification. The unfiltered truncation remains a measured limitation for broad questions on large cases.

## Sorted entities and signed co-observations

The [optimized standard-runner run](https://github.com/ns2switch/irmind/actions/runs/41192440990) uses the same pinned HuntEval commit and synthetic corpus generator as the [baseline run](https://github.com/ns2switch/irmind/actions/runs/41190348193). These are separate GitHub Linux runners of the same class, not guaranteed to be the same physical host. Entity rows are sorted by `(kind, value)` within bounded batches and written with 1,024-row groups and value-column Bloom filters. A signed co-observation artifact stores each entity's record pointer and peers. Neighbor and path queries use it when the case has a complete set; old or mixed cases retain the previous path. Recent timeline queries visit the newest signed date partitions first and stop only when older dates cannot enter the requested top N. Every selected artifact is still rehashed before reading. Page indexes were not enabled because the observed gains came from row-group and Bloom pruning; they need a separate measured comparison before adding write cost.

| Corpus | Baseline ingest | Optimized ingest | Baseline Parquet | Optimized Parquet | Co-observation artifact |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 GB plus 18 episodes | 25.816 s | 40.093 s | 301,259,285 B | 782,415,667 B | 417,450,101 B |
| 15 GB plus 18 episodes | 229.378 s | 447.208 s | 1,803,662,772 B | 8,451,871,774 B | 5,723,788,884 B |

At 15 GB, ingestion remains under the 15-minute target, but the optimized Parquet store uses 6,648,209,002 additional bytes. Co-observations account for most of that increase. The phase measurements in the optimized run were 11.933 s of source hashing, 1,017.292 s of conversion CPU across workers, 157.730 s of row preparation and 284.224 s of Parquet writing; these overlap and do not sum to wall time. This space and write-time tradeoff needs review before applying the design to 500 GB cases.

| Warm 15 GB query p95 | Baseline direct reader | Optimized reader | Former SQL reader |
| --- | ---: | ---: | ---: |
| Term search | 3.162 s | 4.111 s | 7.925 s |
| Entity lookup | 2.306 s | 1.726 s | 1.603 s |
| Neighbors | 8.093 s | 0.578 s | 0.477 s |
| Timeline | 2.650 s | 0.028 s | 1.056 s |
| Direct path | 8.190 s | 0.617 s | 0.470 s |

Entity lookup is 7.7% slower than the former SQL reader, within the 25% target; timeline is faster. Neighbors and direct path are below the 1.5-second p95 target. Term search uses the unchanged event scan: two optimized runs measured 3.206 s and 4.111 s, so the apparent regression against the 3.162-second baseline includes substantial runner variance. The worst measured three-hop path with 200 expansions took 10.056 s and explicitly reported truncation by the unchanged 10-second budget. A broad adversarial path can still be partial; the fast direct-path sample is not a bound for it.

The optimized 15 GB needle check again recovered all 57 malicious events, 30 entities and 42 path segments, with zero parse errors. The highest episode-filtered query p95 remained 0.002 s for each provider. The optimized release binary was 46,734,792 B versus 44,145,224 B for the pinned baseline; Cargo.lock gained no dependencies. The run's warm release test build took 10 s and its separate binary build 56 s; those timings are cache-dependent and are not a cold-build comparison.

## Experimental ECS and OCSF parser ingest

This local, single-worker check used the same machine and test harness for both new parser modules. Each source was generated in a private temporary directory from a synthetic NDJSON record padded to roughly 1 KiB and removed with its derived Parquet after the run. The timed section includes source hashing, guarded parser selection already recorded in the test setup, normalization, signed manifest and audit writes, and Parquet conversion; it excludes source generation and the final explicit `verify`. `CARGO_BUILD_JOBS=1` and one test thread limited memory use. These numbers are local observations, not a standard-runner promise.

| Parser | Synthetic bytes | Timed ingest | Throughput |
| --- | ---: | ---: | ---: |
| ECS NDJSON | 1,073,742,155 | 155.761 s | 6.57 MiB/s |
| OCSF NDJSON | 1,073,742,992 | 170.475 s | 6.01 MiB/s |

The 1 GiB `benchmark_one_gib_synthetic_ingest_per_parser` test in `parser_ingest` remains ignored in ordinary CI; run it manually with Cargo's ignored-test selector and one test thread. OCSF Parquet input has a small synthetic contract test but no 1 GiB throughput claim in this run.
