# Evidence scan benchmarks

Current analyst-approved gates: 15 GB cloud and chronological endpoint ingestion must take less than 900 seconds; disordered endpoint stress ingestion must take less than 1,350 seconds. Existing query targets remain unchanged. See [the final measured gate](#final-v2-ingestion-and-query-gate). Earlier comparisons retain their historical acceptance criteria and workflow outcomes.

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

The implementation now detects the first decreasing record in the parser worker, stops speculation, retains the original hash/metadata snapshot and authenticates the complete fallback parse. It keeps bounded 8 MiB handoffs so ordered throughput does not depend on tiny queues. Each worker prepares its own complete fallback spool, retaining parallel parsing before deterministic sorting and allocation. Real cancellation and parser errors remain errors. Ordered sources use no normalized spool. Temporary-disk accounting includes all retained provisional batch artifacts, not just normalized records; the historical metric name remains `normalized_stage_peak_bytes`.

Both revisions retain 19/19 events, 10/10 entities and 14/14 path checks per cloud provider, with zero parse errors. Historical and active Parquet byte totals match within each pair; that size equality alone is not a full-file hash-equivalence proof. Dedicated reconstruction and byte-equivalence tests cover the writer. Disordered ingestion and some endpoint timelines still fail their unchanged targets in this prototype run. Keep V1 as the default and use the subsequent corrected paired measurements for activation decisions.

### Corrected ordered-source release comparison

The [complete paired release run](https://github.com/ns2switch/irmind/actions/runs/42088793665) compares baseline [`a492613ef967`](https://github.com/ns2switch/irmind/commit/a492613ef967921ecb680f5c03a5912467ee8f22) with candidate [`b03faef4fe0d`](https://github.com/ns2switch/irmind/commit/b03faef4fe0d2a154e61d3ea91b4916e86eef3fb). Each of the nine rows runs both revisions on the same standard Linux runner. Different rows and runs use different runner instances; compare within a pair, not across their absolute times. The [structured results](benchmarks/v2-ordered-write-final.json) retain both frozen revisions, artifact IDs, ZIP SHA-256 values, phase counters, storage and every query p50/p95/error count. Later CI-only changes do not alter the measured Rust or benchmark code.

| 15 GB V2 workload | Before seconds | After seconds | Change | Before / after temporary peak MiB |
| --- | ---: | ---: | ---: | ---: |
| cloud-v2 | 1,002.869 | 968.147 | -3.5% | 134.415 / 16.430 |
| endpoint-v2-1 | 1,243.557 | 1,273.166 | +2.4% | 196.842 / 196.842 |
| endpoint-v2-1-chronological | 578.161 | 471.893 | -18.4% | 134.388 / 12.638 |
| endpoint-v2-1024 | 1,413.465 | 1,447.285 | +2.4% | 196.842 / 196.842 |
| endpoint-v2-1024-chronological | 592.168 | 488.267 | -17.5% | 134.389 / 12.644 |
| endpoint-v2-1025 | 1,249.799 | 1,287.936 | +3.1% | 196.842 / 196.842 |
| endpoint-v2-1025-chronological | 714.692 | 586.189 | -18.0% | 134.389 / 12.644 |
| endpoint-v2-64 | 1,229.691 | 1,267.184 | +3.0% | 196.842 / 196.842 |
| endpoint-v2-64-chronological | 766.100 | 651.776 | -14.9% | 134.389 / 12.644 |

All inputs are 1,000 files and approximately 15.68 decimal GB. Source generation, signed custody and final compaction remain inside the unchanged ingestion wall timer. Hash checks, reconstruction, parser limits, stable ordering, rollback and cancellation are retained. Parquet/co-observation byte totals match within every pair; dedicated byte-equivalence and reconstruction tests, rather than size equality, establish compatibility. The cloud evaluation retains 19/19 malicious events, 10/10 entities and 14/14 path checks for each provider, with zero parse errors in both revisions.

Ordered sources create no normalized-record spool. The nonzero candidate temporary peak includes provisional Parquet files retained for whole-batch rollback. Disordered sources still use the authenticated fallback spool; their 206,404,230-byte peak is unchanged. The cloud pair improves from 1,002.869 to 968.147 seconds and still misses 900 seconds. Chronological endpoints improve, while disordered endpoints regress modestly before the separate natural-run optimization. This comparison does not justify enabling V2.

| Candidate workload | Accumulated staging seconds | Sorting seconds | Replay / writing seconds | Source re-verification seconds | Publication seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| cloud-v2 | 1,790.869 | 0.000 | 656.239 | 12.136 | 0.804 |
| endpoint-v2-1 | 442.061 | 566.099 | 390.248 | 8.180 | 0.689 |
| endpoint-v2-1-chronological | 610.579 | 0.000 | 227.886 | 7.554 | 0.530 |
| endpoint-v2-1024 | 815.753 | 793.813 | 494.944 | 10.884 | 0.769 |
| endpoint-v2-1024-chronological | 644.317 | 0.000 | 240.130 | 7.957 | 0.608 |
| endpoint-v2-1025 | 442.887 | 572.535 | 393.953 | 8.236 | 0.732 |
| endpoint-v2-1025-chronological | 843.717 | 0.000 | 279.426 | 9.486 | 5.463 |
| endpoint-v2-64 | 445.948 | 565.942 | 392.081 | 8.171 | 0.716 |
| endpoint-v2-64-chronological | 901.833 | 0.000 | 290.543 | 9.516 | 8.374 |

Staging sums concurrent worker time and can include backpressure; direct replay can wait for those workers. These counters overlap and are not additive wall percentages. Query deadline failures remain recorded as failures, including those addressed by the separate timeline and entity changes. The full-size workflow therefore stays red where an unchanged ingestion or query target is missed; ordinary code-test CI is independent. Keep V1 as the default until the activation gate is met.

### Parser handoff diagnostic

An intermediate [same-runner cloud pair](https://github.com/ns2switch/irmind/actions/runs/42079404417) compares `efd52a1849f03bf5a40d3d212ec9915d9dbc4339` and `453483105986ee89f54940135bac4283ec50feca`. The [structured observation](benchmarks/v2-small-handoff-prototype.json) records this single completed pair. Other scenarios from that intermediate run are not acceptance results.

Reducing parser handoffs from 8 MiB to 1 MiB raises 15 GB cloud ingestion from 946.036 to 1,042.390 seconds (+10.2%). Sorting is zero in both revisions, so this comparison does not measure the natural-run algorithm. Accumulated staging changes from 1,780.317 to 1,924.831 seconds and replay/writing from 647.649 to 744.071 seconds; they overlap and are not additive wall percentages. Both runs retain 8,924,960,490 Parquet bytes, including 5,960,101,247 co-observation bytes. Neither meets the unchanged 900-second target.

The current ordered-source implementation detects decreasing keys inside each parser worker, retains bounded 8 MiB handoffs and prepares fallback spools in parallel. The natural-run implementation also reuses canonical encoded rows during splitting and merging. New paired measurements isolate that algorithm from the corrected ordered-source baseline. Signed encodings, ordering, quotas, cancellation and source/run hashes remain unchanged.

### Natural-run release comparison

The [complete paired release run](https://github.com/ns2switch/irmind/actions/runs/42089238520) compares baseline [`b03faef4fe0d`](https://github.com/ns2switch/irmind/commit/b03faef4fe0d2a154e61d3ea91b4916e86eef3fb) with candidate [`2049b9cc6eb1`](https://github.com/ns2switch/irmind/commit/2049b9cc6eb13dc793b0ef430e0a001213ae7d3f). Each of the nine rows runs both revisions on the same standard Linux runner. Different rows and runs use different runner instances; compare within a pair, not across their absolute times. The [structured results](benchmarks/v2-natural-run-final.json) retain both frozen revisions, artifact IDs, ZIP SHA-256 values, phase counters, storage and every query p50/p95/error count. Later CI-only changes do not alter the measured Rust or benchmark code.

| 15 GB V2 workload | Before seconds | After seconds | Change | Before / after sorting seconds |
| --- | ---: | ---: | ---: | ---: |
| cloud-v2 | 830.827 | 816.002 | -1.8% | 0.000 / 0.000 |
| endpoint-v2-1 | 1,567.114 | 1,226.869 | -21.7% | 737.249 / 398.252 |
| endpoint-v2-1-chronological | 554.546 | 559.636 | +0.9% | 0.000 / 0.000 |
| endpoint-v2-1024 | 1,442.758 | 1,011.799 | -29.9% | 789.798 / 356.485 |
| endpoint-v2-1024-chronological | 534.332 | 537.598 | +0.6% | 0.000 / 0.000 |
| endpoint-v2-1025 | 1,286.537 | 1,048.640 | -18.5% | 576.995 / 343.507 |
| endpoint-v2-1025-chronological | 560.488 | 560.036 | -0.1% | 0.000 / 0.000 |
| endpoint-v2-64 | 1,459.109 | 1,015.417 | -30.4% | 792.851 / 355.628 |
| endpoint-v2-64-chronological | 503.699 | 498.239 | -1.1% | 0.000 / 0.000 |

All inputs are 1,000 files and approximately 15.68 decimal GB. Source generation, signed custody and final compaction remain inside the unchanged ingestion wall timer. Hash checks, reconstruction, parser limits, stable ordering, rollback and cancellation are retained. Parquet/co-observation byte totals match within every pair; dedicated byte-equivalence and reconstruction tests, rather than size equality, establish compatibility. The cloud evaluation retains 19/19 malicious events, 10/10 entities and 14/14 path checks for each provider, with zero parse errors in both revisions.

The disordered sources contain 15 monotonic runs each. Bounded merging reduces their ingestion by 18–30% and sorting by 40–55%, without changing output bytes. All four still exceed 900 seconds. Cloud and chronological sources require no sort; their small differences are not evidence of a natural-run speedup. Exceeding 32 runs or the merge-head memory bound retains the authenticated external-sort fallback.

| Candidate workload | Accumulated staging seconds | Sorting seconds | Replay / writing seconds | Source re-verification seconds | Publication seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| cloud-v2 | 1,376.144 | 0.000 | 491.554 | 9.488 | 1.568 |
| endpoint-v2-1 | 852.274 | 398.252 | 591.962 | 13.558 | 0.766 |
| endpoint-v2-1-chronological | 966.576 | 0.000 | 331.335 | 10.910 | 0.750 |
| endpoint-v2-1024 | 808.579 | 356.485 | 495.113 | 10.893 | 0.787 |
| endpoint-v2-1024-chronological | 946.618 | 0.000 | 323.559 | 10.813 | 0.696 |
| endpoint-v2-1025 | 438.353 | 343.507 | 388.184 | 8.227 | 0.700 |
| endpoint-v2-1025-chronological | 970.410 | 0.000 | 335.213 | 12.128 | 0.632 |
| endpoint-v2-64 | 807.602 | 355.628 | 497.810 | 10.858 | 0.708 |
| endpoint-v2-64-chronological | 651.421 | 0.000 | 243.551 | 7.901 | 0.586 |

Staging sums concurrent worker time and can include backpressure; direct replay can wait for those workers. These counters overlap and are not additive wall percentages. Query deadline failures remain recorded as failures, including those addressed by the separate timeline and entity changes. The full-size workflow therefore stays red where an unchanged ingestion or query target is missed; ordinary code-test CI is independent. Keep V1 as the default until the activation gate is met.

### Authenticated timeline release comparison

The [complete paired release matrix](https://github.com/ns2switch/irmind/actions/runs/42089799831) compares [baseline `2049b9cc6eb1`](https://github.com/ns2switch/irmind/commit/2049b9cc6eb13dc793b0ef430e0a001213ae7d3f) with [candidate `ab20a08a47f7`](https://github.com/ns2switch/irmind/commit/ab20a08a47f7290c533f7a2625c5875256d233e4). Each of the 18 rows runs both revisions on the same standard Linux runner; rows use separate instances. The [structured results](benchmarks/v2-timeline-final.json) retain frozen revisions, archive SHA-256 values, every scope/query p50/p95 and error count, ingestion phases and storage.

| 15 GB workload | Before global timeline p50 / p95 seconds | After global timeline p50 / p95 seconds | Before / after failed samples (of 5) | Largest filtered timeline p95 after |
| --- | ---: | ---: | ---: | ---: |
| cloud-v1 | 0.015 / 0.019 | 0.247 / 0.256 | 0 / 0 | — |
| cloud-v2 | 0.030 / 0.031 | 0.274 / 0.283 | 0 / 0 | — |
| endpoint-v1-1 | 10.029 / 10.047 | 1.444 / 1.628 | 5 / 0 | 1.706 s (0/5 failed) |
| endpoint-v1-1-chronological | 10.030 / 10.032 | 0.310 / 0.314 | 5 / 0 | 0.343 s (0/5 failed) |
| endpoint-v1-1024 | 10.037 / 10.045 | 1.436 / 1.439 | 5 / 0 | 4.310 s (0/10 failed) |
| endpoint-v1-1024-chronological | 10.028 / 10.031 | 0.311 / 0.314 | 5 / 0 | 4.431 s (0/10 failed) |
| endpoint-v1-1025 | 10.019 / 10.040 | 1.442 / 1.448 | 5 / 0 | 4.178 s (0/10 failed) |
| endpoint-v1-1025-chronological | 10.032 / 10.043 | 0.351 / 0.352 | 5 / 0 | 5.150 s (0/10 failed) |
| endpoint-v1-64 | 10.033 / 10.039 | 1.857 / 1.862 | 5 / 0 | 9.422 s (0/10 failed) |
| endpoint-v1-64-chronological | 10.031 / 10.035 | 0.522 / 0.527 | 5 / 0 | 9.799 s (0/10 failed) |
| endpoint-v2-1 | 10.009 / 10.018 | 0.063 / 0.064 | 5 / 0 | 0.070 s (0/5 failed) |
| endpoint-v2-1-chronological | 7.024 / 7.117 | 0.388 / 0.392 | 0 / 0 | 0.381 s (0/5 failed) |
| endpoint-v2-1024 | 10.012 / 10.022 | 0.077 / 0.078 | 5 / 0 | 0.212 s (0/10 failed) |
| endpoint-v2-1024-chronological | 10.009 / 10.012 | 0.655 / 0.657 | 5 / 0 | 1.737 s (0/10 failed) |
| endpoint-v2-1025 | 10.013 / 10.014 | 0.077 / 0.078 | 5 / 0 | 0.210 s (0/10 failed) |
| endpoint-v2-1025-chronological | 10.005 / 10.007 | 0.466 / 0.470 | 4 / 0 | 1.443 s (0/10 failed) |
| endpoint-v2-64 | 10.010 / 10.012 | 0.058 / 0.059 | 5 / 0 | 0.019 s (0/10 failed) |
| endpoint-v2-64-chronological | 6.700 / 6.800 | 0.290 / 0.316 | 0 / 0 | 0.036 s (0/10 failed) |

All eight V1 endpoint global timelines previously failed all five samples; the candidate worst p95 is 1.862 seconds. The V2 endpoint worst global p95 is 0.657 seconds with zero errors. Cloud global timelines rise from 0.019 to 0.256 seconds for V1 and 0.031 to 0.283 seconds for V2 because authenticated statistics discovery adds metadata work to an already short query. This is a real small-query regression, still well below the unchanged deadline. The table reports it rather than treating every query as faster.

Statistics are read only after hashing each file against its signed artifact. Unknown/inexact extrema cannot prune. File and row-group ordering uses conservative time bounds, then the shared stable source/offset key for ties. V1 whole-second ties use authenticated source/index statistics or a narrow reference-column projection for compacted mixed-source groups. A candidate is skipped only when its bound is strictly worse than the retained cutoff. Metadata discovery and projected reads share the existing 10-second budget; cancellation remains active. The public timeline remains newest-first, while internal ascending and descending paths are tested against full scans. No new signed metadata or port fields are needed.

| 15 GB workload | Before ingestion seconds | After ingestion seconds | After Parquet GB | After co-observation GB |
| --- | ---: | ---: | ---: | ---: |
| cloud-v1 | 379.108 | 411.400 | 8.452 | 5.724 |
| cloud-v2 | 946.284 | 941.902 | 8.925 | 5.960 |
| endpoint-v1-1 | 185.117 | 179.513 | 2.390 | 0.481 |
| endpoint-v1-1-chronological | 175.941 | 173.447 | 2.390 | 0.481 |
| endpoint-v1-1024 | 184.190 | 178.578 | 2.393 | 0.481 |
| endpoint-v1-1024-chronological | 173.619 | 170.817 | 2.392 | 0.481 |
| endpoint-v1-1025 | 182.917 | 176.522 | 2.393 | 0.481 |
| endpoint-v1-1025-chronological | 210.723 | 204.830 | 2.392 | 0.481 |
| endpoint-v1-64 | 194.372 | 192.655 | 2.392 | 0.481 |
| endpoint-v1-64-chronological | 214.726 | 211.845 | 2.392 | 0.481 |
| endpoint-v2-1 | 1,188.605 | 1,166.651 | 2.814 | 1.249 |
| endpoint-v2-1-chronological | 523.902 | 520.854 | 6.604 | 1.798 |
| endpoint-v2-1024 | 1,003.197 | 997.576 | 2.758 | 1.224 |
| endpoint-v2-1024-chronological | 713.626 | 710.096 | 6.476 | 1.762 |
| endpoint-v2-1025 | 1,021.349 | 1,011.117 | 2.759 | 1.224 |
| endpoint-v2-1025-chronological | 555.157 | 543.541 | 6.479 | 1.763 |
| endpoint-v2-64 | 1,031.257 | 1,025.825 | 2.814 | 1.249 |
| endpoint-v2-64-chronological | 495.180 | 500.117 | 6.608 | 1.798 |

The writer and signed encodings are unchanged in this reader optimization. Ingestion includes source generation, signed custody and final compaction; these timing differences are not a claimed writer speedup. Candidate V2 cloud and disordered controls still miss 900 seconds in this pair. Other query failures remain in the JSON, including cloud entity lookup addressed separately. The paired workflow stays failed if either revision misses any unchanged target; passing global timelines alone does not close the ingestion gate.

Both cloud writers retain 19/19 malicious events, 10/10 entities and 14/14 path checks per provider, with zero parse errors. Tests compare exact bounded/full-scan order for mixed generations, unknown and submicrosecond instants, legacy same-second compacted groups and both directions. A changed older artifact still fails authentication even when its time bound would exclude it. No hash or corruption check is skipped to obtain the latency result.

### Entity-extrema release comparison

The [complete paired release matrix](https://github.com/ns2switch/irmind/actions/runs/42090681509) compares a profiling-only [baseline `53e281238c6a`](https://github.com/ns2switch/irmind/commit/53e281238c6a247ddbebf0b7763e371cfe133fcd) with [candidate `3504cfc58ada`](https://github.com/ns2switch/irmind/commit/3504cfc58ada428f6546728f1ba9f630c536e18b). Each row runs both revisions in release mode on the same standard Linux runner. Rows use separate runner instances; absolute times from different rows or earlier matrices are not controlled speedup measurements. The [structured results](benchmarks/v2-entity-final.json) retain all 18 pairs, revisions, archive SHA-256 values, p50/p95 for every scope/query, counters, storage, initial summaries and failures.

| 15 GB workload | Before entity p50 / p95 seconds | After entity p50 / p95 seconds | Before / after failed samples (of 5) |
| --- | ---: | ---: | ---: |
| cloud-v1 | 4.881 / 5.003 | 4.079 / 4.092 | 0 / 0 |
| cloud-v2 | 8.635 / 8.712 | 4.447 / 4.580 | 0 / 0 |
| endpoint-v1-1 | 6.038 / 6.160 | 5.079 / 5.332 | 0 / 0 |
| endpoint-v1-1-chronological | 4.841 / 4.867 | 4.195 / 4.206 | 0 / 0 |
| endpoint-v1-1024 | 0.309 / 0.310 | 0.311 / 0.312 | 0 / 0 |
| endpoint-v1-1024-chronological | 0.243 / 0.246 | 0.241 / 0.244 | 0 / 0 |
| endpoint-v1-1025 | 0.245 / 0.245 | 0.245 / 0.246 | 0 / 0 |
| endpoint-v1-1025-chronological | 0.299 / 0.300 | 0.303 / 0.308 | 0 / 0 |
| endpoint-v1-64 | 0.394 / 0.402 | 0.390 / 0.393 | 0 / 0 |
| endpoint-v1-64-chronological | 0.466 / 0.558 | 0.462 / 0.464 | 0 / 0 |
| endpoint-v2-1 | 9.824 / 9.901 | 4.370 / 4.424 | 0 / 0 |
| endpoint-v2-1-chronological | 8.132 / 8.243 | 3.680 / 3.715 | 0 / 0 |
| endpoint-v2-1024 | 0.617 / 0.680 | 0.636 / 0.682 | 0 / 0 |
| endpoint-v2-1024-chronological | 0.446 / 0.488 | 0.460 / 0.495 | 0 / 0 |
| endpoint-v2-1025 | 0.524 / 0.558 | 0.507 / 0.553 | 0 / 0 |
| endpoint-v2-1025-chronological | 0.680 / 0.721 | 0.690 / 0.729 | 0 / 0 |
| endpoint-v2-64 | 0.437 / 0.437 | 0.365 / 0.373 | 0 / 0 |
| endpoint-v2-64-chronological | 0.645 / 0.647 | 0.530 / 0.554 | 0 / 0 |

The historical same-runner V1/V2 entity comparison was 5.788 versus 9.396 seconds p95. The current matched V2 pair isolates the conversion overhead: entity p95 falls from 8.712 to 4.580 seconds (47.4%), with zero errors. Counting matches and finding first/last instants previously formatted every precise timestamp as RFC 3339 before aggregating it. It also repeated source-binding lookups and owned-key allocation. The optimized internal time-only projection keeps physical timestamps, compares borrowed keys, formats only the final extrema and reuses the immediately preceding validated binding within an immutable Arrow batch. Every changed source hash, null hash/index and offset unit is still validated. Other display projections keep their existing formatted output.

| Cloud V2 entity phase, mean accumulated seconds per query | Before | After |
| --- | ---: | ---: |
| Hash verification | 0.624168 | 0.622699 |
| Scan, including nested normalization | 17.974636 | 9.516951 |
| Normalization | 4.990762 | 0.112866 |
| Aggregation | 2.035705 | 2.049264 |

Counters average five samples and sum worker durations. Scan includes normalization, and workers overlap; do not add these columns or present them as wall-time percentages. Hash-verification work is essentially unchanged. The matched data identifies avoidable conversion and allocation cost rather than a reason to remove verification.

### Final V2 ingestion and query gate

| 15 GB V2 workload | Ingestion seconds | Approved limit | Gate met | Largest query p95 across scopes | Query errors / samples | Initial graph summary seconds |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| cloud-v2 | 865.973 | 900 s | yes | 4.580 s | 0 / 25 | 3.351 |
| endpoint-v2-1 | 1,120.179 | 1,350 s | yes | 4.567 s | 0 / 50 | 3.739 |
| endpoint-v2-1-chronological | 508.475 | 900 s | yes | 3.776 s | 0 / 50 | 3.295 |
| endpoint-v2-1024 | 1,007.507 | 1,350 s | yes | 1.810 s | 0 / 75 | 4.493 |
| endpoint-v2-1024-chronological | 488.131 | 900 s | yes | 3.067 s | 0 / 75 | 3.110 |
| endpoint-v2-1025 | 1,101.840 | 1,350 s | yes | 1.385 s | 0 / 75 | 3.620 |
| endpoint-v2-1025-chronological | 559.978 | 900 s | yes | 4.207 s | 0 / 75 | 5.234 |
| endpoint-v2-64 | 1,071.745 | 1,350 s | yes | 1.275 s | 0 / 75 | 3.228 |
| endpoint-v2-64-chronological | 561.596 | 900 s | yes | 4.602 s | 0 / 75 | 4.927 |

The analyst-approved release gate is strictly below 900 seconds for 15 GB cloud and chronological endpoint ingestion. The disordered endpoint corpus is a stress workload with a separately approved strict limit of 1,350 seconds (1.5 times the release limit). Query targets, including ordinary and overflow host queries, remain unchanged. All final candidate rows meet their current workload gate. This is an analyst decision about acceptance, not an additional measured optimization. Historical workflow conclusions and raw measurements are retained: those runs evaluated the former 900-second stress limit. The complete historical workflow remains failed where either revision missed its then-current target; a successful candidate query is not evidence that an entire pair passed. V1 filtered query failures also remain in the JSON rather than being omitted. These measurements do not establish a speed guarantee for every runner or arbitrary evidence. Earlier pairs include slower cloud instances; use their matched deltas, not a favorable cross-run comparison.

The initial graph summary is the first summary after ingestion, not a measurement after evicting the operating-system page cache. Ingestion wall time includes source generation, signed custody and final compaction. Storage accounting and query sampling occur afterward. All inputs contain 1,000 files and about 15.68 decimal GB.

| Candidate V2 workload | Accumulated staging seconds | Sorting seconds | Replay / writing seconds | Source re-verification seconds | Publication seconds | Temporary peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cloud-v2 | 1,434.638 | 0.000 | 498.111 | 9.516 | 5.738 | 16.430 |
| endpoint-v2-1 | 579.535 | 355.127 | 441.935 | 9.447 | 2.399 | 196.842 |
| endpoint-v2-1-chronological | 664.405 | 0.000 | 248.011 | 8.037 | 0.633 | 12.638 |
| endpoint-v2-1024 | 807.041 | 355.374 | 493.821 | 10.888 | 0.807 | 196.842 |
| endpoint-v2-1024-chronological | 646.305 | 0.000 | 241.214 | 7.911 | 0.601 | 12.644 |
| endpoint-v2-1025 | 581.367 | 357.759 | 435.565 | 9.476 | 1.231 | 196.842 |
| endpoint-v2-1025-chronological | 963.312 | 0.000 | 333.167 | 12.182 | 0.660 | 12.644 |
| endpoint-v2-64 | 441.165 | 346.648 | 395.051 | 8.204 | 0.741 | 196.842 |
| endpoint-v2-64-chronological | 957.612 | 0.000 | 331.871 | 12.092 | 0.630 | 12.644 |

Staging sums concurrent workers, and direct replay can include producer waits. These phases overlap and are not additive wall percentages. Temporary peaks include retained provisional files needed for whole-batch rollback; chronological sources do not create a normalized-record spool. All per-pair Parquet/co-observation byte totals match. Byte-equivalence and reconstruction tests validate content compatibility independently of these sizes.

Both cloud writers preserve 19/19 malicious events, 10/10 entities and 14/14 path checks per provider, with zero parse errors. Bounded worst-case paths still report time-budget truncation; no sample, expansion or deadline limit was raised. The [co-observation proposal](coobservation-reference-proposal.md) records the storage trade-off without implementing a schema change.

### Remaining disordered-ingestion work

The final four disordered cases take 1,007.507–1,120.179 seconds, below the analyst-approved 1,350-second stress limit. Further optimization is [tracked in issue #186](https://github.com/ns2switch/irmind/issues/186), after v0.2.0, and does not block that release. Sorting and replay/writing remain the largest measured sequential costs. Natural-run merging still writes an intermediate merged stream, copies it back into the normalized spool and parses that spool again before writing Parquet.

Next, measure splitting, merging, final copying and replay separately, then evaluate feeding the bounded merge directly into the existing provisional Parquet writer. Retain every run count/size/hash check at EOF, full-source authentication, deterministic partition allocation, stable order, cancellation and whole-batch rollback. Keep the current external-sort fallback above the run/head bounds. Require byte-equivalence and failure-cleanup tests and repeat all 15 GB pairs. The present counters do not measure the potential saving of that fusion, so no estimated sub-900 result is claimed. Keep the 900-second release gate for cloud and chronological sources and the 1,350-second stress gate for disordered sources. Query limits do not change.

## Isolated EVTX conversion

A release build of the separate helper workspace converted a synthetic EVTX file of 1,073,680,384 bytes (approximately 1 GiB) in 13.01 seconds: 78.73 MiB/s, 229,362 records and three precise Parquet artifacts. This covers initial/source rehashing, contained decoding, normalization and Parquet conversion; audit signing is excluded. The fixture repeats the synthetic Security mapping chunk with chronological record-header times. It is not a compressed/template-heavy real-world EVTX corpus or a query benchmark. No original evidence copy is made. The release helper executable measured 1,468,960 bytes on Linux x86-64.

Reproduce with the separately resolved workspace:

```sh
CARGO_TARGET_DIR=target cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked --example benchmark
CARGO_TARGET_DIR=target cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked --bin irmind-evtx
target/release/examples/benchmark
```

The benchmark rejects unoptimized execution and removes its temporary source and artifacts on exit. Repeated local release runs took 13.01–19.64 seconds (52.12–78.73 MiB/s); filesystem-cache and background-load variation prevents interpreting this range as an optimization result.


### Small EVTX collection and session witness

The release-only `collection` example generates 300 distinct synthetic files of 69,632 bytes (20,889,600 bytes total). Each has a different authenticated record-header timestamp and valid chunk checksums, avoiding duplicate-source cache hits. The expected output is 4,200 records and 900 precise Parquet artifacts. It removes sources, runtime directories and artifacts on exit.

| Native platform | Collection conversion | Full network witness | Witness executions |
| --- | ---: | ---: | ---: |
| Linux x86-64 | 10.58 s | Not applicable: per-child seccomp/Landlock checks | 0 |
| Windows Server 2025 x86-64 | 20.347 s | 1.040 s | 1 |

This measures source hashing/re-verification, contained decoding, normalization and precise Parquet conversion. It excludes audit signing and fixture generation. The [signed candidate run](https://github.com/ns2switch/irmind/actions/runs/42273621946) contains the Windows measurement JSON. Windows parser startup takes 1.131 s, including the 1.040 s witness; do not add both figures. Windows additionally measures the first full network witness separately; the collection uses the same parser session for all 300 files. Service changes or validation failures require a new witness rather than a cached success.

```sh
CARGO_TARGET_DIR=target cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked --example collection
CARGO_TARGET_DIR=target cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked --bin irmind-evtx
target/release/examples/collection
```

### Large Security EVTX collections

The `large_collection` example uses a generated, entirely synthetic Security log with event-specific fields for 4624, 4625, 4688, 4634 and 4672. Each 64 KiB chunk holds 64 events. Record headers and XML record IDs agree, timestamps advance in 100 ms steps while retaining their 100 ns remainder, and user names rotate across 1,024 synthetic values. Host and documentation-range IP addresses are synthetic. This corpus exercises approximately 1 KiB per record; it does not claim coverage of every Windows template or real incident workload.

The two collections contain 100 MiB and 1 GiB of chunks, plus file headers. The latter uses four sources of 256 MiB plus a 4 KiB header each. They use the application's signed V2 ingestion use case, followed by a complete chain/artifact verification and an exact indexed-record count. Ingestion timing includes hashing, the contained decoder, normalization, Parquet and audit signatures. Fixture generation, initial sandbox setup and final verification are separate. The parent is the release ingestion host, not the interactive TUI or a model process. Its synthetic signing key is restricted to the temporary benchmark case.

The manual **Weekly fuzzing** workflow input `evtx_large=true` runs only this benchmark on Linux and Windows. It builds the normal-feature decoder after the benchmark host so test-only broker features do not enter the auxiliary executable. No external provider is used. The Windows network witness still performs its approved local positive controls.

Memory is the largest observed per-process OS high-water resident set (Linux) or peak working set (Windows), sampled every 20 ms. Auxiliary values are the maximum individual child, not the sum of concurrent children. Sampling can miss a short-lived process or a final spike; the harness refuses a successful result with no observed parent or decoder memory. Sources, provisional artifacts and runtime directories are removed after each collection.

A separate in-process production-decoder check uses one dense 1 GiB source. It checks the exact record bound without changing it, consumes frames without retaining the stream and requires rejection without a completion trailer. Its time is not included in contained-ingestion throughput or memory measurements. The initial baseline used 1,000,000 records, at most 8 GiB of output (also limited to 32 times source size plus 1 MiB), a 4 MiB frame and 600 seconds per contained decoding invocation.

The benchmark accepts a developer-only batch size of one or four sources (`evtx_batch_files` in the manual workflow). Every result records that size. A per-source run uses the same signed application case of use for each file in the existing case; it is a separate qualification from a four-source batch. Do not present its timings as default batch results. The parser's native isolation and all quotas remain identical.

[Source scheduling](parser-source-scheduling.md) describes the optional parser capability and the Windows serial contract. The baseline measurements below precede that implementation and the new 8,000,000-record ceiling.

#### Native batch-of-four qualification

[Native run](https://github.com/ns2switch/irmind/actions/runs/42314854568), release source `e7511f43fdcea85fff7862c4ab1f66498eb73f20`. MiB/s uses actual authenticated source bytes including headers. Memory is observed MiB under the sampling method above.

| Platform | Corpus | Sources | Records verified | Ingestion | MiB/s | Parent peak MiB | Helper peak MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux x86-64 | 100 MiB + header | 1 | 102,400 | 6.357 s | 15.73 | 89.18 | 3.20 |
| Linux x86-64 | 1 GiB + headers | 4 | 1,048,576 | 61.988 s | 16.52 | 209.45 | 3.27 |
| Windows x86-64 | 100 MiB + header | 1 | 102,400 | 5.490 s | 18.21 | 72.93 | 5.55 |
| Windows x86-64 | 1 GiB + headers | 4 | Not qualified in this run | — | — | — | — |

The Windows partial artifact contains only the completed 100 MiB case. It does not establish a 1 GiB batch result. The completed collections reached no record, output or invocation-time limit. Windows startup took 1.121 s and used one full session witness. Each 256 MiB source contains 262,144 records; each has the unchanged 8 GiB output cap. The 100 MiB source has a 3,356,622,848-byte output budget. Final verification is separate: 0.055/0.493 s on Linux and 0.053 s for Windows 100 MiB.

The separate Linux in-process decoder check uses a single source of 1,073,745,920 bytes containing 1,048,576 events. It emits exactly 1,000,000 records and rejects the remainder without a completion trailer, taking 16.348 s. This is an intentional record-bound qualification, not a successful ingestion or a contained-worker memory measurement.

Data: [Linux collection and limit JSON](https://github.com/ns2switch/irmind/actions/runs/42314854568/artifacts/13550257924), [completed Windows 100 MiB JSON](https://github.com/ns2switch/irmind/actions/runs/42314854568/artifacts/13552457222). Per-source measurements with batch size one are a separate qualification.

#### Native per-source qualification

[Per-source native run](https://github.com/ns2switch/irmind/actions/runs/42320713853), release source `7dd4698a775e6ac35fe469afbfa032ec63e64837`, passed on both platforms. Each application request contains one source (`batch_files=1`); the four-source 1 GiB corpus still uses one case and one parser session. This characterizes the supported per-file workflow. It does not qualify the Windows batch-of-four path above.

| Platform | Corpus | Sources | Records verified | Ingestion | MiB/s | Parent peak MiB | Helper peak MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux x86-64 | 100 MiB + header | 1 | 102,400 | 6.565 s | 15.23 | 91.21 | 3.16 |
| Linux x86-64 | 1 GiB + headers | 4 | 1,048,576 | 64.884 s | 15.78 | 133.28 | 3.53 |
| Windows x86-64 | 100 MiB + header | 1 | 102,400 | 5.650 s | 17.70 | 74.93 | 5.70 |
| Windows x86-64 | 1 GiB + headers | 4 | 1,048,576 | 54.634 s | 18.74 | 93.09 | 6.17 |

Both 1 GiB cases verified 15 artifacts and 20 signed entries. No collection reached its per-file record, output or 600-second invocation bound. Windows used one witness per parser session: startup, including the witness, took 1.132 s for 100 MiB and 1.700 s for 1 GiB. Final verification took 0.051/0.470 s on Windows and 0.054/0.478 s on Linux. Peak memory covers each process lifetime, including setup/probes and verification; it excludes the compiler and the independent Python sampler.

The separate dense single-file decoder check rejected at exactly 1,000,000 of 1,048,576 records, without a completion trailer, on Linux (16.075 s) and Windows (13.018 s). These checks call the production decoding library in-process. They do not constitute a successful whole-file ingestion or test the contained worker's wall deadline.

Data: [Linux collection and limit JSON](https://github.com/ns2switch/irmind/actions/runs/42320713853/artifacts/13552921558), [Windows collection and limit JSON](https://github.com/ns2switch/irmind/actions/runs/42320713853/artifacts/13552508622). Both native jobs used optimized release builds and removed their synthetic sources and artifacts. Differences between the two Linux run modes are not an optimization result: they are separate runner executions.

#### Eight-million-record qualification

The decoder and parent validator now allow 8,000,000 records per file. Source size remains at most 4 GiB, each protocol frame at most 4 MiB, output at most the smaller of 8 GiB and 32 times source bytes plus 1 MiB, and each invocation at most 600 seconds. Limit diagnostics name the bound and state that the complete source was rejected.

The extended release benchmark qualifies a four-source Windows request with one session witness, isolated one-file 1 GiB ingestion on both platforms, a near-4 GiB file on Linux, and a compact synthetic source with exactly 8,000,000 records on both platforms. The source cannot be exactly 4 GiB because an EVTX consists of a 4 KiB header and whole 64 KiB chunks; the maximum aligned source is 4,294,905,856 bytes. A separate in-process negative check has 8,000,128 records and requires rejection at the exact ceiling without a completion trailer. Its memory is not mixed with the contained ingestion measurement.

The compact fixture uses valid, minimal Security event fields and 128 records per chunk. It is a streaming-resource stress corpus, distinct from the richer five-event Security corpus used for throughput. Its timestamps advance by 100 ns to hold date cardinality constant for the memory comparison. It is measured at 204,800, 2,097,152 and 8,000,000 records; the last source is 4,096,004,096 bytes. Results will distinguish the two corpora and retain the earlier measurements as baselines.
