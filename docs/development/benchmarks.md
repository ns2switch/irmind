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

The 1 GiB `benchmark_one_gib_synthetic_ingest_per_parser` test in `parser_ingest` remains ignored in ordinary CI; run it manually with Cargo's ignored-test selector and one test thread. OCSF Parquet input has a small synthetic contract test but no 1 GiB throughput claim in this run. [Issue #61](https://github.com/ns2switch/irmind/issues/61) tracks the 25 MiB/s target without reducing parser limits.

## Experimental DFIR parser ingest

The same local, single-worker harness measured the five DFIR parsers on one synthetic 1 GiB source each. The measured interval covers hashing, parser selection, normalization, Parquet conversion and signed custody writes. It excludes fixture generation and the final explicit verification. Each run used a private temporary case directory that was removed afterwards. These are local measurements, not a standard-runner guarantee.

| Parser | Format | Synthetic bytes | Timed ingest | Throughput |
| --- | --- | ---: | ---: | ---: |
| Velociraptor | JSONL | 1,073,742,201 | 133.364 s | 7.68 MiB/s |
| Hayabusa | JSONL | 1,073,742,752 | 136.713 s | 7.49 MiB/s |
| Chainsaw | JSONL | 1,073,742,965 | 123.149 s | 8.32 MiB/s |
| plaso | JSONL | 1,073,741,994 | 111.110 s | 9.22 MiB/s |
| EZTools | CSV | 1,073,742,432 | 237.634 s | 4.31 MiB/s |

The benchmark uses repeated small records and a complete local ingest, so the numbers include costs outside the parser itself. The low CSV and JSONL throughput needs profiling before setting a release target.

With default features and the same `cargo build -p irmind --release --locked` profile, the main-branch binary measured 47,733,368 B and the binary with these five parsers measured 48,314,232 B (+580,864 B, 1.22%). The workspace lockfile rose from 539 to 546 packages: five local parser crates plus `csv` and `csv-core`.

## Declarative parser

The local default-feature release build ingested 1,073,742,492 bytes of synthetic NDJSON in **15.478 seconds (66.16 MiB/s)**. The corpus repeats one nested custom authentication event with 800 padding bytes; source generation is excluded. The timed operation includes source hash, streaming mapping, entity/co-observation Parquet and signed custody. Subsequent case verification passed. This single-file repeated-data result is not comparable to the earlier heterogeneous DFIR benchmark or a standard GitHub runner. It does not close the shared throughput investigation in issue #61.

Reproduce with the ignored `benchmark_declarative_one_gib` integration test in `crates/bin/tests/declarative.rs`, using a release build and one local build job if memory is limited. The test owns a temporary directory, checks the signed case and removes source and artifacts on completion. It is not run in ordinary PRs.

| Same local default-feature Linux release build | Before (main `52bb023`) | Declarative draft |
| --- | ---: | ---: |
| Binary bytes | 48,391,864 | 49,145,152 |
| Change | — | +753,288 (+1.56%) |

Both binaries reported `irmind 0.1.3` and used the same Rust toolchain, release profile and existing dependency cache. Build times were warm/incremental and are not a cold-build comparison. The new lockfile resolves the same third-party packages; it adds only the IRMind parser crate.

### Declarative detection matrix

Native fixture scores remain unchanged. Every declarative candidate is below the automatic-selection threshold (80%). Here `—` means no match; the native DFIR diagonal is 95%. The three example definitions do not match any native fixture.

| Fixture | JSON | Its native ECS/OCSF/DFIR parser | custom-access | custom-nested | custom-auth | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| JSON/cloud | 90 | — | — | — | — | JSON automatically |
| ECS | 45 | 95 | — | — | — | ECS automatically |
| OCSF JSON | 45 | 95 | — | — | — | OCSF automatically |
| Velociraptor / Hayabusa / Chainsaw / plaso | 45 | 95 | — | — | — | Corresponding native parser automatically |
| EZTools CSV | — | 95 | — | — | — | EZTools automatically |
| Custom CSV | — | — | 70 | — | — | Analyst choice |
| Custom nested NDJSON | 45 | — | — | 70 | — | Analyst choice |
| Custom authentication text | — | — | — | — | 70 | Analyst choice |

The versioned matrix test checks every native fixture against the three declarations and every custom fixture against all native parsers and declarations. Shared streaming contracts cover all three declarative formats. Low confidence deliberately requires selection even with one candidate; no false high-confidence declarative match was observed.

Nightly AddressSanitizer fuzzing of detection and parsing ran **600 seconds**, exercising **1,042,080 inputs**, with no crashes and peak RSS 385 MiB under a 512 MiB limit. Disposable corpora and artifacts were removed. The target also runs in weekly fuzzing.

## Experimental syslog parser

The synthetic 1 GiB test uses roughly 1 KiB RFC 5424 rows and the selected-parser, signed-source pipeline used by the TUI. Sources are generated immediately before ingestion, so the OS page cache is warm. This measurement uses the pinned Rust toolchain, an **optimized release build** with all features, local Linux x86_64 and one build/test worker. It is not a standard-runner or parser-only claim. Fixture generation is excluded; the timed operation includes format detection, source hashing, normalization, extraction, Parquet/co-observation output and signed custody. Explicit case verification runs afterwards. No model, network service or real incident data is used.

| Measure | Optimized release result |
| --- | --- |
| Source baseline | main `369ddc9` |
| Synthetic source | 1,073,741,832 bytes |
| Selected-source ingestion | 15.803 s |
| End-to-end throughput | 64.798 MiB/s |
| Post-ingestion verification | passed |
| All-feature release binary | 49,369,984 bytes |

Reproduce by selecting the ignored `syslog_one_gib_ingestion_throughput` test in `crates/bin/tests/syslog_ingest.rs`, using Cargo’s release profile, all features, locked dependencies and one build/test worker. The ignored benchmark refuses a build with debug assertions, so unoptimized performance numbers cannot be recorded by mistake. Its temporary source and case directory are removed after completion. The approved per-ingestion correction was then measured again on the same equipment and optimized profile: **1,073,741,832 bytes in 11.247 s (91.050 MiB/s)**, with verification passing. The earlier **64.798 MiB/s** result remains the optimized baseline. The current all-feature release binary is 49,609,224 bytes (baseline 49,369,984 bytes). A single repeat is not an attributed optimization claim: CPU load and the OS cache vary. Neither result closes issue #61.

The parser's first ASAN fuzz run completed its 600-second budget without failure. A second run seeded with valid gzip completed normally after 602.850 seconds including its incremental build: 2,392,307 executions, 7,661 new units, peak RSS 441 MiB, zero failures. Two 600-second runs amount to 0.333 hours of local fuzzing. Each uses a temporary corpus removed on exit, at most 64 KiB per input, a 1 GiB RSS limit and a 30-second per-input timeout. These runs cover the integrated v1 parser, not the pending temporal-context changes.

### Syslog detection matrix

Values are confidence percentages for the versioned public fixtures; `—` means no match. The three example declarative definitions match none of these native fixtures. Existing native scores are unchanged.

| Fixture | JSON | ECS | OCSF | Velociraptor | Hayabusa | Chainsaw | plaso | EZTools | Syslog |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| JSON/cloud | 90 | — | — | — | — | — | — | — | — |
| ECS | 45 | 95 | — | — | — | — | — | — | — |
| OCSF JSON | 45 | — | 95 | — | — | — | — | — | — |
| Velociraptor | 45 | — | — | 95 | — | — | — | — | — |
| Hayabusa | 45 | — | — | — | 95 | — | — | — | — |
| Chainsaw | 45 | — | — | — | — | 95 | — | — | — |
| plaso | 45 | — | — | — | — | — | 95 | — | — |
| EZTools CSV | — | — | — | — | — | — | — | 95 | — |
| Syslog RFC 5424 | — | — | — | — | — | — | — | — | 95 |

No high-confidence false positive or tie was observed in this matrix. Unit contracts separately check RFC 3164 (90%) and content-detected gzip. New frozen fixtures add 18 byte/hash pairs covering syslog normalization, source manifests and actual Parquet artifact envelopes; the original 67 pairs remain unchanged under both JSON map implementations.

## Experimental Linux parser

Each synthetic input below is generated before timing on the same local Linux x86_64 machine as the syslog correction, using the pinned toolchain, all features and an **optimized release build**. One test/build worker is used; freshly generated files have a warm OS cache. The timed selected-parser pipeline includes sampling/detection, hashing and source checks, typed parsing, extraction, Parquet/co-observation writing and signed custody. Generation and the subsequent successful case verification are excluded. No real data, network or model is used. These are local measurements, not a standard-runner claim or a stage-level profile.

| Linux input | Bytes | Ingestion | Throughput | Case verification |
| --- | ---: | ---: | ---: | --- |
| auth.log / secure | 1,073,741,824 | 15.274 s | 67.043 MiB/s | passed |
| journald JSON | 1,073,742,725 | 15.832 s | 64.680 MiB/s | passed |
| HTTP combined | 1,073,742,485 | 13.388 s | 76.485 MiB/s | passed |
| correlated auditd | 1,073,742,975 | 13.234 s | 77.377 MiB/s | passed |

Rows are approximately 1 KiB. Audit records have unique event serials and a complete syscall/execve/end-marker group, so repeated serial collisions or rejected records do not inflate the result. The other inputs retain their format-specific metadata. Do not compare these numbers as identical schemas or as an improvement over earlier unoptimized results. The release-only ignored test `linux_one_gib_release_throughput` in `crates/bin/tests/linux_ingest/benchmark.rs` recreates all four files and refuses debug-assertion builds. Each temporary source/case is deleted before the next format.

A second release run added an explicit zero-rejected-record assertion for every source. It passed, as did case verification. With ASAN fuzzing competing for CPU, timings were auth 19.954 s (51.319 MiB/s), journald 17.512 s (58.475 MiB/s), HTTP 24.234 s (42.255 MiB/s) and auditd 12.976 s (78.916 MiB/s). Keep the workload difference visible; neither run is a controlled comparison with the other.

The detection matrix adds the four Linux public fixtures at 95%, with no other native high-confidence match. Journald JSON also receives the existing generic JSON score of 45%, so the unique native match wins. PRI-prefixed syslog retains its existing detector; Linux does not compete for it. Declarative confidence remains at most 70%, with explicit analyst choice. The existing nine native fixtures keep their scores.

Linux adds 24 new frozen byte/hash pairs for normalized output, manifests and actual Parquet artifact envelopes. All 85 historical pairs remain unchanged. The extra Linux test is part of the existing `format_goldens` target, so the preserve_order CI job compares it too. A dedicated detect/parse fuzz target and synthetic seeds are included in the weekly job; the local run is reported with the delivery PR.

### Linux detection matrix

The versioned detection test asserts every score below; `—` means no match. The three existing declarative examples match none of these native fixtures. Their own fixtures each select the corresponding definition at 70% and require analyst confirmation.

| Fixture | JSON | ECS | OCSF | Velociraptor | Hayabusa | Chainsaw | plaso | EZTools | Syslog | Linux |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| JSON/cloud | 90 | — | — | — | — | — | — | — | — | — |
| ECS | 45 | 95 | — | — | — | — | — | — | — | — |
| OCSF JSON | 45 | — | 95 | — | — | — | — | — | — | — |
| Velociraptor | 45 | — | — | 95 | — | — | — | — | — | — |
| Hayabusa | 45 | — | — | — | 95 | — | — | — | — | — |
| Chainsaw | 45 | — | — | — | — | 95 | — | — | — | — |
| plaso | 45 | — | — | — | — | — | 95 | — | — | — |
| EZTools CSV | — | — | — | — | — | — | — | 95 | — | — |
| Syslog RFC 5424 | — | — | — | — | — | — | — | — | 95 | — |
| Linux auth.log | — | — | — | — | — | — | — | — | — | 95 |
| Linux auditd | — | — | — | — | — | — | — | — | — | 95 |
| Linux journald JSON | 45 | — | — | — | — | — | — | — | — | 95 |
| HTTP common/combined | — | — | — | — | — | — | — | — | — | 95 |

No high-confidence false positive or tie occurred in this fixture matrix. Authentication lines with PRI stay with syslog; native Linux handles unprefixed authentication exports. The current all-feature release binary is 49,889,720 bytes, versus 49,609,224 bytes on its syslog base (+280,496 bytes). Cargo.lock grows from 564 to 565 packages solely for the local Linux module; external packages and versions are unchanged.

The local Linux detect/parse ASAN fuzz run completed a 600-second budget (601 seconds reported by libFuzzer): **2,519,363 executions, 28,248 new units, 516 MiB peak RSS, zero failures**. Build and execution took 653.860 seconds. Inputs are at most 64 KiB with a 1 GiB RSS bound and 30-second per-input timeout. The public seeds, mutated corpus, failure directory and log used for this run were held in a temporary directory and removed on exit. This is 0.167 hours for the new Linux parser; it is not a claim of exhaustive coverage.


## Timestamp and host-partition comparison

The release-only benchmark compares the current V1 writer with the explicit V2 writer using identical source bytes and four-source batches on the same standard Linux runner. V1/V2 here identify artifact writers, not retired parser versions; both use current readers. It retains the 1 GB and 15 GB CloudTrail corpus and adds 15 GB journald endpoint corpora with exactly 1, 64, 1,024 and 1,025 hosts. Each endpoint file belongs to one host; the extra 24/25 hosts share the first files so the 1,000-file corpus contains every declared host. The production Linux parser preserves source microseconds. Source generation and parser selection are deterministic; both writers record an explicit parser selection.

The wall timer includes source generation, file writes/removal, selected-parser ingestion, signed custody and final compaction. The phase counters exclude source generation. Compare the two writers on the same scenario; these wall measurements are not isolated parser throughput.

Each 15 MB endpoint file repeats its 1 MB slab 15 times. The source microseconds therefore run backwards at 14 slab boundaries per file. V2 must externally sort those sources; V1 collapses their instants to the same second. This workload includes required stable-order work, not only host partitioning. The V2 sorting counter measures that pass. A separate chronological endpoint control is needed before attributing the whole slowdown to partition cardinality or treating the cap as optimal.

`PARQUET_SCENARIO` identifies each measurement. `PARQUET_INGEST` retains hash, conversion, row preparation, Parquet-write and wall times. `normalized_stage_peak_bytes` measures the peak live normalized-source staging across workers, excluding originals and published artifacts. V1 does not use that staging path. `PARQUET_LAYOUT` reports signed historical and lineage-active files, partitions, ordinary hosts, overflow artifacts and their bytes. Compaction inputs remain signed historical files. `PARQUET_COLUMN` reports compressed column bytes, including time, precision, scope and co-observation columns.

Query samples retain SHA-256 verification and the existing result, sampling, expansion and 10-second limits. Five samples report p50/p95 for term search, entity lookup, neighbors, timeline and path. Endpoint runs compare unfiltered queries, an ordinary host and the final host, which enters signed overflow above the initial 64-host cap. Cloud runs retain the independent HuntEval needles and bounded three-hop worst-path case. Generated corpus files are removed after each ingested batch to bound disk use; the case is removed after each scenario. This benchmark does not retain the full original corpus for a later reconstruction. Separate reconstruction contracts cover that behavior. These are benchmarks of synthetic data, not sizing guarantees for arbitrary endpoint logs.

The workflow accepts a specific scenario for reproducing a measured failure. A full comparison continues through the remaining workloads if one fails, then returns a failing status; individual query and ingestion targets are unchanged. The host-cap recommendation and result tables are filled from the workflow output before production V2 writing is enabled. The hard ceiling remains 1,024. No runtime limit is relaxed by the benchmark.


### Initial standard-runner measurement

The [initial release run](https://github.com/ns2switch/irmind/actions/runs/41936657135) completed unsuccessfully. The [machine-readable measurements](benchmarks/artifact-v2-initial.json) retain its observed results, not acceptance claims. All scenarios used the same standard Linux runner and source commit. No timing below comes from an unoptimized build.

| Scenario | Input GB | Ingestion seconds | Parquet GB | Co-observation GB | Normalized staging peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| cloud-v1 (15gb) | 15.686 | 308.245 | 8.452 | 5.724 | 0.000 |
| cloud-v1 (1gb) | 1.046 | 33.019 | 0.782 | 0.417 | 0.000 |
| endpoint-v1-1 (15gb) | 15.676 | 112.184 | 2.390 | 0.481 | 0.000 |
| endpoint-v1-64 (15gb) | 15.676 | 115.244 | 2.392 | 0.481 | 0.000 |
| endpoint-v1-1024 (15gb) | 15.676 | 111.085 | 2.393 | 0.481 | 0.000 |
| endpoint-v1-1025 (15gb) | 15.676 | 111.963 | 2.393 | 0.481 | 0.000 |
| endpoint-v2-1 (15gb) | 15.676 | 1259.540 | 2.814 | 1.249 | 196.842 |
| endpoint-v2-64 (15gb) | 15.676 | 1251.331 | 2.814 | 1.249 | 196.842 |
| endpoint-v2-1024 (15gb) | 15.676 | 1233.883 | 2.758 | 1.224 | 196.842 |
| endpoint-v2-1025 (15gb) | 15.676 | 1220.351 | 2.759 | 1.224 | 196.842 |

V1 CloudTrail passed the ingestion and sampled-query targets at both sizes. On 15 GB, p95 was 2.546 s for term search, 3.706 s for entity lookup, 0.502 s for neighbors, 0.019 s for timeline and 0.500 s for path. HuntEval retained 19/19 malicious events, 10/10 entities and 14/14 path checks for each provider, with zero parse errors, in the reference, 1 GB and 15 GB corpora. The bounded worst-case path took 10.001 s and explicitly reported time-budget truncation.

V1 endpoint timelines hit the unchanged 10-second deadline in all four host workloads. The first query failure prevented the original harness from collecting later unfiltered/host-filtered measurements. V2 endpoint ingestion took 1,220–1,260 seconds, exceeding the 900-second target; its original ingestion assertion prevented query sampling. The cloud V2 workloads stopped when the benchmark inserted HuntEval without the required explicit parser selection. This is an invalid benchmark call, not a reason to bypass that requirement.

The original conversion, row and Parquet counters cover V1 only. Their V2 zeroes mean uninstrumented phases, not zero work. V1 accumulated worker durations overlap and must not be added or presented as percentages of wall time. The normalized staging peak is 206,404,230 bytes (196.842 MiB); it excludes published Parquet and original sources. The new optional V2 counters separate parsing/normalized staging, sorting, spool replay/partitioned writing, original re-verification and consolidation/publication. Staging accumulates concurrent worker time; the later phases are sequential within a prepared batch. These counters record no source content.

All four endpoint V1 cases store 8,696,000 compressed bytes in `event_time`, compared with 291,496,017–298,855,350 in V2 across the recorded artifacts. This is not a type-only integer-versus-string comparison: V1 collapses the synthetic microseconds to repeated whole seconds, whereas V2 retains the distinct instants. The JSON measurement records every compressed column, including the new precision/scope metadata. Aggregate Parquet grows from about 2.39 GB to 2.76–2.81 GB, with co-observation growing from about 0.48 GB to 1.22–1.25 GB.

### Complete profiled run

The [profiled standard-runner run](https://github.com/ns2switch/irmind/actions/runs/41984151442) completed all 12 timed scenarios on one runner, in release mode. It failed the existing targets. Its [raw measurements](benchmarks/artifact-v2-profiled.json) identify the frozen source commit, `26885cf2f4061c0970f5adde55af696e683c61aa`. Compare V1 and V2 within this run; absolute times from separate runners are not a controlled before/after comparison.

| Scenario | Ingestion seconds | Parquet GB | Co-observation GB | Temporary staging peak MiB |
| --- | ---: | ---: | ---: | ---: |
| cloud-v1 (15gb) | 530.670 | 8.452 | 5.724 | 0.000 |
| cloud-v1 (1gb) | 53.548 | 0.782 | 0.417 | 0.000 |
| endpoint-v1-1 (15gb) | 194.199 | 2.390 | 0.481 | 0.000 |
| endpoint-v1-64 (15gb) | 192.285 | 2.392 | 0.481 | 0.000 |
| endpoint-v1-1024 (15gb) | 193.037 | 2.393 | 0.481 | 0.000 |
| endpoint-v1-1025 (15gb) | 192.942 | 2.393 | 0.481 | 0.000 |
| cloud-v2 (15gb) | 1149.683 | 8.925 | 5.960 | 134.415 |
| cloud-v2 (1gb) | 106.714 | 0.820 | 0.435 | 9.081 |
| endpoint-v2-1 (15gb) | 1554.457 | 2.814 | 1.249 | 196.842 |
| endpoint-v2-64 (15gb) | 1555.721 | 2.814 | 1.249 | 196.842 |
| endpoint-v2-1024 (15gb) | 1532.162 | 2.758 | 1.224 | 196.842 |
| endpoint-v2-1025 (15gb) | 1539.551 | 2.759 | 1.224 | 196.842 |

V2 endpoint ingestion is about eight times slower than its matching V1 runs. Cloud V2 takes 1,149.683 s for 15 GB, versus 530.670 s for V1. All V2 15 GB workloads exceed the unchanged 900-second target.

| V2 scenario | Parallel staging (accumulated seconds) | Sorting (seconds, wall share) | Replay/writing (seconds, wall share) | Source re-verification seconds | Per-source publication seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| cloud-v2 (15gb) | 1518.791 | 0.000 (0.0%) | 439.526 (38.2%) | 13.850 | 0.931 |
| cloud-v2 (1gb) | 113.816 | 0.000 (0.0%) | 30.136 (28.2%) | 0.976 | 0.555 |
| endpoint-v2-1 (15gb) | 797.788 | 737.661 (47.5%) | 373.859 (24.1%) | 13.851 | 0.760 |
| endpoint-v2-64 (15gb) | 795.831 | 738.858 (47.5%) | 374.252 (24.1%) | 13.840 | 0.743 |
| endpoint-v2-1024 (15gb) | 794.470 | 738.015 (48.2%) | 363.501 (23.7%) | 13.873 | 0.747 |
| endpoint-v2-1025 (15gb) | 799.355 | 739.346 (48.0%) | 365.153 (23.7%) | 13.848 | 0.751 |

Sorting takes 47–48% of endpoint wall time, and replay/writing takes about 24%. The staging column sums overlapping workers; it is not a wall percentage and must not be added to the sequential percentages. Generation, staging wall time, signed custody, final case compaction and other orchestration account for the remaining wall time. Publication here measures source consolidation/publication, not final case compaction. No timer justifies removing hashing, source re-verification or stable ordering.

All five general CloudTrail queries completed without errors. Their V2 15 GB p95 values were term search 4.740 s, entity lookup 9.396 s, neighbors 0.739 s, timeline 0.028 s and path 0.743 s. The V1 values were 5.217 s, 5.788 s, 0.650 s, 0.023 s and 0.638 s respectively.

| V2 endpoint hosts | Signed scope partitions | Worst ordinary-host query p95 | Worst overflow-host query p95 | Unfiltered timeline p95 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 1 | 10.033 s (entity deadline); timeline also fails | not applicable | 10.016 s (deadline) |
| 64 | 64 | 0.205 s | not applicable | 10.013 s (deadline) |
| 1,024 | 65 | 0.712 s | 0.714 s | 10.013 s (deadline) |
| 1,025 | 65 | 0.774 s | 0.715 s | 10.013 s (deadline) |

Every failing entity/timeline label above had five failed samples. Ordinary and overflow queries for 64 or more hosts had zero errors. V1 endpoint timelines fail both without a host filter and with one. Its host-filtered term, entity and neighbor queries also hit the deadline; filtered paths return at the time budget and still fail the latency target. A zero error count alone is not a claim that a bounded path was exhaustive.

V1 retains full HuntEval recall at 1 GB and 15 GB: each provider has 19/19 events, 10/10 entities, 14/14 path checks and zero parse errors. The initial profiled V2 evaluation stopped at the first legacy AWS episode: its records have no provider or region, but the evaluator supplied a region from the dataset directory. Those V2 recall and worst-path results are **not collected**, not zero and not passed. The evaluator now uses only a provider fallback explicitly declared consistently in source records; directory attribution does not create a query predicate. Exact source pointers, event/entity checks, path assertions, query limits and private-answer isolation remain unchanged. The release reference test now ingests and reconstructs all 18 episodes with both writers; all reference checks pass for AWS, Azure and GCP. Full-size validation is recorded separately from the matched performance run.

The warm infrastructure test build took 15 s. The first default-feature CLI build in that job took 401 s and produced a 51,545,776-byte binary. This is a cache-dependent CLI build measurement, not a clean-workspace cold-build claim. Both measurements belong to the frozen run commit, rather than to later documentation or warning changes.

### Full-size V2 needle validation

The [cloud-only validation run](https://github.com/ns2switch/irmind/actions/runs/42013703628), at commit `8842bc73a18c3ee66c856caf8f4619a5eca55420`, repeats the two CloudTrail workloads with the corrected source-based evaluator. The [recorded validation](benchmarks/artifact-v2-cloud-validation.json) includes the paired V1/V2 reference checks and full-size V2 results. It runs on a separate standard runner; the lower wall times are not a measured ingestion optimization or a replacement for the matched V1/V2 comparison.

At both 1 GB and 15 GB, each provider retains **19/19 events, 10/10 entities and 14/14 path checks**, with zero parse errors. The 18 episodes are also reconstructed independently with both writers. Original-pointer, timeline-order and private-answer isolation assertions remain active. Parquet byte totals match the corresponding V2 workloads in the profiled run.

| V2 workload | Ingestion seconds | General query outcome | Worst bounded three-hop path |
| --- | ---: | --- | --- |
| CloudTrail 1 GB | 95.419 | all five labels pass; largest p95 0.599 s | not run at this size |
| CloudTrail 15 GB | 1,001.320 | entity lookup: 1/5 samples fails, p95 10.036 s; other labels pass | 10.002 s; explicitly truncated by the time budget |

The 15 GB term, neighbors, timeline and path p95 values are 3.807 s, 0.757 s, 0.035 s and 0.764 s. This run still fails: ingestion exceeds 900 s and one entity-lookup sample reaches the query deadline. Correct HuntEval recall does not close those performance targets. Its warm infrastructure test build takes 14 s; the first default-feature CLI build takes 399 s and produces 51,600,488 bytes, at this run's own source commit.

### Ordered endpoint control (local, 1 GB)

A separate local diagnostic uses 1,000 endpoint files, 64 hosts and 1,045,072,000 identical source bytes per writer. Each file has one chronological slab, so V2 does not need an external sort. Both writers run sequentially with the same optimized release binary, one build/test worker and five samples per query. This is not a standard-runner acceptance result or a comparison with the 15 GB runner's absolute times. The [machine-readable control](benchmarks/artifact-v2-local-control.json) records every sample summary and phase counter.

| Writer | Ingestion seconds | Parquet MB | Co-observation MB | Unfiltered timeline p95 | Host-filtered entity p95 (worst of two hosts) | Host-filtered timeline p95 (worst of two hosts) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| V1 | 51.831 | 159.784 | 30.484 | 1.494 s | 6.531 s | 10.005 s (all five samples per host failed) |
| V2 | 101.629 | 425.656 | 112.074 | 0.415 s | 0.015 s | 0.012 s |

All V2 queries passed. V1 correctly fails the query target because both host-filtered timelines reach the unchanged 10-second deadline. V2 reports 19.040 s of accumulated parallel staging, less than 0.001 s of sorting, 34.730 s of sequential replay/writing, 0.779 s of source re-verification and 17.764 s of publication. Its temporary staging peak is 9,388,000 bytes. The V2 ingestion overhead persists without sorting; the local pair is about 1.96 times slower for ingestion, while host-filtered queries benefit from partition pruning. This control does not measure overflow or determine the best cap.

### Host-cap recommendation and remaining gate

Keep **64 hosts per case as the provisional default**, with the approved **1,024 hard ceiling**. This run created 1, 64 and 65 scope partitions for the 1-host, 64-host and larger cases; the latter retain 64 ordinary hosts plus signed overflow. Values beyond the cap remain available in row columns and entity queries. Raising the cap is not supported as an ingestion fix: V2 wall times differ by only about 3% across these workloads, while the shared V2 path is roughly eleven times slower than V1.

The profiled run supports retaining 64 as a conservative starting cap: it bounds large cases to 65 scope buckets and keeps measured ordinary/overflow filtered queries below 0.8 s with 64, 1,024 and 1,025 source hosts. It still varies source cardinality under a fixed cap, so it does not establish that 64 is optimal or measure an alternative cap. Global endpoint timelines and the one-host aggregate remain over budget, and 15 GB V2 ingestion remains over 15 minutes. Keep production V2 writing disabled and step (e) open. Prioritize the external-sort and spool replay paths, then the unfiltered timeline; retain exact ordering, cancellation, signed allocations, rollback and hash checks. Re-measure the unchanged corpus and an additional chronological endpoint control before enabling the writer.


### Same-runner ordered-write prototype

The [paired release run](https://github.com/ns2switch/irmind/actions/runs/42062238235) compares baseline `e0c23b603dc581ab8a1146c08f94d3aa8311729b` with prototype `2afce210ba7d5564aa36ef9ee88e9b179211d035`. Each row runs both revisions on the same standard Linux runner. The [structured metrics](benchmarks/v2-ordered-write-prototype.json) retain artifact IDs, download SHA-256 values, phase counters, layout, query p50/p95 and errors. These timings predate immediate speculative-parser restart and are not final optimization acceptance results.

| 15 GB V2 workload | Baseline seconds | Prototype seconds | Change |
| --- | ---: | ---: | ---: |
| cloud-v2 | 758.306 | 675.129 | -11.0% |
| endpoint-v2-1 | 1,487.275 | 1,938.262 | +30.3% |
| endpoint-v2-1-chronological | 627.333 | 524.809 | -16.3% |
| endpoint-v2-1024 | 1,247.763 | 1,595.456 | +27.9% |
| endpoint-v2-1024-chronological | 703.962 | 547.298 | -22.3% |
| endpoint-v2-1025 | 1,219.913 | 1,607.066 | +31.7% |
| endpoint-v2-1025-chronological | 697.302 | 554.597 | -20.5% |
| endpoint-v2-64 | 1,470.019 | 1,929.690 | +31.3% |
| endpoint-v2-64-chronological | 710.338 | 561.777 | -20.9% |

Cloud ingestion improves by 11%; chronological endpoint ingestion improves by 16–22%. The disordered workloads regress by 28–32% because the prototype finishes its speculative parse before reading the source again for sorting. For 64 hosts, accumulated staging rises from 544.055 to 3,284.603 seconds, while sorting remains about 661–666 seconds and replay/writing rises from 319.301 to 573.886 seconds. Staging includes concurrent parser backpressure; these values are not additive wall-clock percentages.

The implementation now detects the first decreasing record in the parser worker, stops speculation, retains the original hash/metadata snapshot and authenticates the complete fallback parse. It keeps bounded 8 MiB handoffs so ordered throughput does not depend on tiny queues. Real cancellation and parser errors remain errors. Ordered sources use no normalized spool. Temporary-disk accounting includes all retained provisional batch artifacts, not just normalized records; the historical metric name remains `normalized_stage_peak_bytes`.

Both revisions retain 19/19 events, 10/10 entities and 14/14 path checks per cloud provider, with zero parse errors. Historical and active Parquet byte totals match within each pair; that size equality alone is not a full-file hash-equivalence proof. Dedicated reconstruction and byte-equivalence tests cover the writer. Disordered ingestion and some endpoint timelines still fail their unchanged targets in this prototype run. Keep V1 as the default and use the subsequent corrected paired measurements for activation decisions.
