# Evidence scan benchmarks

Current measured targets are 900 seconds for 15 GB cloud/chronological ingestion and 1,350 seconds for disordered stress. The approved 1,025-host stress ingestion miss is nonblocking; ordinary query limits remain required. See the [current policy](#current-policy-sole-mapped-v3-writer). Earlier comparisons retain their historical acceptance criteria and workflow outcomes.

This page is for maintainers comparing signed Parquet ingestion and bounded evidence queries. The [manual and weekly workflow](../../.github/workflows/graph-benchmark.yml) generates synthetic 1 GB and 15 GB corpora on a standard Linux runner. It uploads the raw output. No corpus or original evidence is kept as an artifact.

## Current policy: sole mapped V3 writer

The pre-1.0 policy removes comparative writer gates. Keep absolute 15 GB ingestion goals of 900 seconds for cloud/chronological input and 1,350 seconds for disordered stress. The 1,025-host stress case is measured and tracked as nonblocking work in [issue #218](https://github.com/ns2switch/irmind/issues/218), which links #186 and #214. Every ordinary query must still complete without errors or time-budget truncation and below ten seconds. The deliberate expansive path stays a reported diagnostic and must retain an explicit partial-result marker when its budget truncates it.

The [current-format measurements](benchmarks/v3-absolute-measurements.json) select only the recorded mapped candidate. Their provenance pins the immutable source JSON and its SHA-256. Corpus labels are descriptive, measured durations are unchanged, and successful worst-path status follows the source harness's result unwrap. No comparison implementation is required by the evaluator.

The [absolute evaluation](benchmarks/v3-absolute-targets.json) reports `passed: true` and `all_ingest_goals_met: false`: all required absolute checks pass, while the 1,025-host stress sample remains 1,363.429 seconds against its 1,350-second goal. This does not relabel that miss as a measured success. These are measurements of the recorded pipeline; the completed decoder/mapping rollout still requires current release measurements.

Earlier paired sections below are historical measurements and decisions, not current activation requirements.

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

#### Local streaming-memory reference

[Raw release results](benchmarks/evtx-streaming-local.json), source `341c7184cb525d87ecc6c90e089cd0d796d1a681`. This is a local reference, separate from hosted Linux and Windows qualification. Every source completed signed V2 ingestion, full chain/artifact verification and the exact indexed-record count. Memory is the sampled process high-water value over the complete host lifetime, including final verification.

| Corpus | Records | Ingestion | MiB/s | Host peak MiB | Decoder peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rich Security, maximum aligned source below 4 GiB | 4,194,240 | 151.270 s | 27.08 | 714.66 | 3.05 |
| Compact Security, 100 MiB | 204,800 | 4.614 s | 21.67 | 89.62 | 3.11 |
| Compact Security, 1 GiB | 2,097,152 | 57.926 s | 17.68 | 245.00 | 3.06 |
| Compact Security, 8,000,000 records | 8,000,000 | 183.048 s | 21.34 | 621.36 | 3.05 |

The single near-4 GiB source fits the unchanged 8 GiB output budget and 600-second decoder deadline. The compact cases keep one date and host partition. Decoder memory is stable in these measurements; complete-host memory is not constant. The [bounded-metadata design](parquet-bounded-metadata-design.md) proposes profiling and a separately versioned, bounded-segment writer without changing existing signed generations. It is not implemented in these figures.

#### Native scheduling and eight-million-record results

[Release run](https://github.com/ns2switch/irmind/actions/runs/42353376005), source `341c7184cb525d87ecc6c90e089cd0d796d1a681`. Both native jobs passed: Linux in 21 min 12 s and Windows in 23 min 35 s, including compilation, corpus creation, verification and the independent negative probe. This is a new runner execution, not a controlled before/after optimization comparison.

Every collection uses `batch_files=4`. The four-source cases are one application request. Single-file cases are distinct and validate the complete source. Windows uses one network witness per collection's parser session. All counts are verified through signed V2 ingestion, chain/artifact verification and the graph summary.

| Platform | Security corpus | Records verified | Ingestion | MiB/s | Host peak MiB | Decoder peak MiB | Witnesses |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux | 100 MiB | 102,400 | 6.573 s | 15.22 | 92.04 | 3.17 | 0 |
| Linux | 1 GiB, four files | 1,048,576 | 63.111 s | 16.23 | 213.54 | 3.42 | 0 |
| Linux | 1 GiB, one file | 1,048,576 | 65.010 s | 15.75 | 244.91 | 3.19 | 0 |
| Linux | near 4 GiB, one file | 4,194,240 | 258.868 s | 15.82 | 749.23 | 3.28 | 0 |
| Windows | 100 MiB | 102,400 | 9.460 s | 10.57 | 73.18 | 5.74 | 1 |
| Windows | 1 GiB, four files | 1,048,576 | 76.852 s | 13.32 | 91.23 | 6.03 | 1 |
| Windows | 1 GiB, one file | 1,048,576 | 75.889 s | 13.49 | 154.97 | 5.95 | 1 |

The Linux near-4 GiB source is the maximum aligned EVTX size, 4,294,905,856 bytes. It verifies 18 artifacts and 20 signed entries. Both four-file 1 GiB cases verify 15 artifacts and 20 signed entries; both single-file 1 GiB cases verify six artifacts and eight entries. None reaches its record, frame, output-byte or 600-second invocation limit. The measured whole-ingestion times of the single-file cases are also below 600 seconds. Acceptance applies to these versioned synthetic fixtures, not every Windows template or possible expansion ratio.

The compact corpus holds host/date cardinality constant while increasing record count:

| Platform | Records verified | Ingestion | MiB/s | Host peak MiB | Decoder peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Linux | 204,800 | 9.677 s | 10.33 | 80.38 | 3.20 |
| Linux | 2,097,152 | 100.843 s | 10.15 | 234.65 | 3.18 |
| Linux | 8,000,000 | 383.448 s | 10.19 | 690.90 | 3.21 |
| Windows | 204,800 | 11.908 s | 8.40 | 74.13 | 5.39 |
| Windows | 2,097,152 | 123.741 s | 8.28 | 176.45 | 5.83 |
| Windows | 8,000,000 | 462.807 s | 8.44 | 465.57 | 5.87 |

Both 8,000,000-record sources complete with three artifacts and five signed entries. Decoder memory remains approximately stable; the complete host's memory grows, so these measurements do not close a constant-host-memory criterion. [Bounded Parquet metadata](parquet-bounded-metadata-design.md) is separate work, with a reviewed builder contract required before implementation. This EVTX change does not implement it or change existing builder identities.

The separate in-process negative probe uses 8,000,128 records and rejects at exactly 8,000,000 with no completion trailer: 70.373 s on Linux and 77.939 s on Windows. It qualifies the production library's exact record bound; it is not a contained-ingestion memory or wall-deadline measurement.

Raw JSON: [Linux](https://github.com/ns2switch/irmind/actions/runs/42353376005/artifacts/13567156971), [Windows](https://github.com/ns2switch/irmind/actions/runs/42353376005/artifacts/13566834546). Sources, provisional data and native runtime directories are removed after each collection. No external model or provider is used; Windows retains its approved local network-witness positive controls.

## Historical network parser prototype

The same local release-profile, single-file harness measured the network parsers. The timed interval includes source hashing, parsing, entity extraction, Parquet conversion with co-observations, and signed custody. Fixture generation and the final explicit `verify` are excluded. These measurements are local and do not establish throughput on a standard runner.

| Parser | Format | Synthetic bytes | Timed ingest | Throughput |
| --- | --- | ---: | ---: | ---: |
| Zeek | TSV | 1,073,742,288 | 18.419 s | 55.59 MiB/s |
| Suricata | EVE JSONL | 1,073,743,067 | 30.054 s | 34.07 MiB/s |

Both benchmarks used one Cargo job and one test thread, with private temporary case directories removed after the run. These figures belong to the unmerged pre-V2 prototype and its legacy second-resolution writer. That prototype was not distributed in v0.1.x. Current V2 qualification is recorded separately below; do not treat the old figures as current-module throughput.

## Network parsers with precise V2 artifacts

[Raw optimized results](benchmarks/network-v2-ingest.json), source `e090bb6a42f1b11a3100ec7b36cee2a34bca23ed`. The same local Linux release build ran three repetitions per selected parser, with one source and a fresh case per repetition. Sources repeat synthetic records with padding to at least 1 GiB. They are generated immediately before ingestion, so their source cache is warm. These are local measurements, not standard GitHub-runner gates and not a controlled optimization comparison with the unmerged historical prototype.

Timing includes source hashing, bounded parsing/entity extraction, precise V2 Parquet with real record offsets and co-observations, and signed custody. Generation and final verification are excluded. Every run verifies all three artifact hashes and the exact indexed count; sources, cases and private temporary directories are removed. No model or remote service is used.

| Parser | Source bytes | Records per run | Repetition times, s | Median, s | Median MiB/s | MiB/s range |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| parser-zeek | 1,073,742,539 | 1,097,896 | 21.005, 36.604, 24.292 | 24.292 | 42.15 | 27.97–48.75 |
| parser-suricata | 1,073,743,067 | 861,061 | 23.762, 25.310, 24.360 | 24.360 | 42.04 | 40.46–43.09 |

Zeek's larger spread is retained rather than selecting its fastest run. The corpus is repetitive and compresses well; this does not predict heterogeneous incident throughput. Reproduce with the ignored `benchmark_one_gib_synthetic_ingest_per_parser` test in `crates/bin/tests/parser_ingest.rs`, an optimized release build and the nonsecret development selector `IRMIND_BENCH_PARSER` set to `zeek` or `suricata`. The harness refuses an unoptimized run.

### Network detection coverage

The [complete captured confidence matrix](benchmarks/network-detection-matrix.json) has 19 public text fixtures and 16 registered detectors, including the declarative holder and three signed example definitions. Every native fixture has exactly one high-confidence winner; the generic JSON fallback is 45 where applicable. Declarative fixtures remain at 70 and require analyst choice; no unexpected high-confidence match was observed. The EVTX binary/native-readiness suite is separate, and the existing OCSF Parquet header check remains an analyst-choice case. The matrix is captured from the same registry test used in CI, not hand-written detector expectations.

### Network parser fuzzing

Both detection and parsing entry points completed 600-second AddressSanitizer runs on synthetic/mutated seeds with no crash or timeout. The input bound was 64 KiB, the per-case timeout 30 seconds and the process RSS limit 512 MiB. These runs cover bounded in-memory fuzz inputs; the separate streaming regressions cover oversized first lines. [Run settings and exit status](benchmarks/network-v2-fuzz.json) record both completed runs. Quiet libFuzzer output did not report execution counts. Temporary mutation corpora were removed.

## Common-schema core: initial iteration

The opt-in unclassified common bridge was compared with `d13ce8b` in [paired release jobs](https://github.com/ns2switch/irmind/actions/runs/42389530821). Candidate `31e57eb` uses the new schema IDs. Each completed pair uses the same GitHub-hosted Ubuntu runner. These are intermediate results, not a passing common-writer gate.

| Synthetic 15 GB scenario | Baseline seconds | Common seconds | Existing limit | Candidate meets ingestion limit |
| --- | ---: | ---: | ---: | --- |
| Cloud | 947.159 | 1,374.256 | 900 | no |
| Disordered endpoint, 1 host | 1,154.095 | 1,664.101 | 1,350 | no |
| Disordered endpoint, 64 hosts | 1,003.102 | 1,509.744 | 1,350 | no |

The matched cloud baseline also exceeded 900 seconds. Its successful entity-query p95 was 5.629 seconds; the common candidate reached its deadline in all five entity samples (elapsed p95 10.058 seconds, **no successful result**). Candidate cloud neighbors/path p95 were 1.754/1.665 seconds. Cold summaries succeeded. The deliberately expansive worst-case path remained marked as truncated by its time budget. HuntEval probes retained full event/entity/path recall for all three providers, with no parse error.

The cloud smoke used 1,077,119,172 bytes in each of three repetitions: 120.728, 120.837 and 121.021 seconds. Six further full-matrix scenarios were cancelled after the completed pairs demonstrated the regression. The endpoint smoke and complete matrix are not established by this iteration. [Machine-readable results](benchmarks/common-core-initial-run.json) retain failures, query counts, profiles, column sizes and smoke repetitions. Parallel phase intervals overlap; do not sum them as wall time. The current CLI/TUI writer and existing gates are unchanged.

### Byte-preserving staging diagnostic

The following diagnostic uses optimized release builds on the same local execution host, three repetitions per revision. It is **not** a GitHub-runner result or a projection of 15 GB performance. Fifty files represent 50 hosts under the 64-host cap, with the full 15-run disordered source shape: 783,804,000 bytes per repetition.

| Revision | Wall-time samples, seconds | Median seconds | Total Parquet bytes | Co-observation bytes |
| --- | --- | ---: | ---: | ---: |
| `51aa808`, repeated staging cache | 79.598 / 68.801 / 79.220 | 79.220 | 101,058,989 | 38,289,257 |
| `075b506`, derived cache restored on read | 54.696 / 58.471 / 54.989 | 54.989 | 101,058,989 | 38,289,257 |

The median is 30.6% lower in this reduced diagnostic. The change omits a redundant peer-JSON cache from the unsigned spool, restores it before memory accounting and batch construction, reuses canonical legacy entity pairs, and avoids a second timestamp-extrema pass for a retained homogeneous scope. Memory budgets and final schemas stay fixed. The dedicated round-trip test compares all three Arrow batches and their Parquet bytes; existing physical goldens remain unchanged. Equal total sizes in this diagnostic alone are not a full-corpus hash-equality proof. The absent `endpoint-0063` filter is retained in [raw numeric results](benchmarks/common-core-staging-diagnostic.json) but its empty-result timings are not populated-host latency measurements.

The initial cloud co-observation layout additionally stores role-free peers twice. The [adopted sparse representation](common-event-peer-layout.md) is a separate change from these byte-preserving staging optimizations. It retains the same logical peers and historical layouts, while updating only the new common co-observation physical goldens. A complete 15 GB remeasurement is required before changing a default writer.

## Common-schema core: sparse peer matrix

The [complete paired release run](https://github.com/ns2switch/irmind/actions/runs/42398461520) compares common candidate `60823af` with baseline `d13ce8b`. Every pair uses the same GitHub-hosted Ubuntu runner; different pairs use separate VMs. The 64 ordinary-host cap and 1,024 hard ceiling stay fixed. Only the unclassified bridge is measured; these figures do not establish the cost or coverage of future parser mappings. [Numeric results, profiles and column sizes](benchmarks/common-core-sparse-run.json) retain every completed pair and failed sample.

The wall timer includes corpus generation/writes, signed ingestion, source cleanup, HuntEval source staging where applicable and final compaction. Builds and the subsequent query measurements are excluded. Sources are written immediately before ingestion; no OS cache flush is claimed. Query p95 is the largest of five samples for each label/scope. Failed samples are errors, not successful ten-second responses. The first summary is labelled cold by the harness; this is not a cold-page-cache experiment.

| Synthetic 15 GB corpus | Baseline, s | Common, s | Ingest limit, s | Ingest meets limit | Failed common query samples |
| --- | ---: | ---: | ---: | --- | ---: |
| cloud-v2 | 950.500 | 1155.245 | 900 | no | 5 |
| endpoint-v2-1 | 1021.145 | 1258.894 | 1350 | yes | 0 |
| endpoint-v2-64 | 1180.877 | 1533.259 | 1350 | no | 0 |
| endpoint-v2-1024 | 1019.924 | 1300.330 | 1350 | yes | 0 |
| endpoint-v2-1025 | 999.898 | 1350.493 | 1350 | no | 0 |
| endpoint-v2-1-chronological | 565.661 | 769.969 | 900 | yes | 10 |
| endpoint-v2-64-chronological | 593.437 | 739.811 | 900 | yes | 0 |
| endpoint-v2-1024-chronological | 599.495 | 767.924 | 900 | yes | 0 |
| endpoint-v2-1025-chronological | 553.663 | 756.066 | 900 | yes | 0 |

Overall, ingestion passes in 6/9 scenarios, sampled-query checks in 7/9, and the combined benchmark in 5/9. Of 575 labelled full-corpus query samples, 560 return without error and 15 reach the deadline. This count excludes the separately reported HuntEval probes and deliberately expansive path.

Three candidate smoke repetitions use at least 1 GiB per run:

| Source shape | Bytes per repetition | Wall-time samples, s |
| --- | ---: | --- |
| cloud-v2 | 1,077,119,172 | 102.507 / 101.470 / 101.444 |
| endpoint-v2-64-chronological | 1,076,450,200 | 82.625 / 72.341 / 66.406 |

The candidate remains opt-in and does **not** meet the unchanged complete-matrix gate. Cloud ingestion exceeds 900 seconds; the matched cloud baseline also exceeds that threshold. Common entity lookup reaches its deadline in cloud and the one-host chronological corpus. The disordered 64-host and 1,025-host ingests also exceed their 1,350-second limit; the latter misses by 0.493 seconds and is not rounded into a pass. Normal CLI/TUI/demo writing remains on the existing V2 builder.

For cloud, total retained Parquet is 10,146,332,714 bytes versus the matched baseline's 8,924,960,490. Common co-observations occupy 6,349,418,440 bytes; the initial complete-descriptor iteration occupied 12,712,715,750. This storage comparison does not turn timings from different runner instances into a controlled speedup. The raw JSON records active/historical file counts, all five query labels and host filters, per-column compressed bytes, HuntEval recall and bounded worst-case-path markers.

Tracked normalized-staging peaks are 19,500,830 bytes for common cloud, 286,019,970 for disordered endpoint and 15,667,791 for the one-host chronological endpoint in the measured run. These are tracked staging bytes, not total process memory or total temporary disk usage. Parallel phase timers overlap; scan timers include backpressure. Scoped aggregation is not separately timed, so its zero aggregate counter cannot establish zero CPU cost. Full reconstruction, custody and typed-role correctness also have separate functional tests; the performance harness deletes generated sources batch by batch.

## Source decoding, mapped V3 and retained layout parents

This release benchmark is for evidence-store and mapping maintainers. It measures the complete decoder → frozen mapper → validated writer path, including signed receipts and physical compaction. It uses extraction-only cloud and journald modules, not empty projections or semantic mappings.

[Run 42514919987](https://github.com/ns2switch/irmind/actions/runs/42514919987) compares [candidate 783da1c](https://github.com/ns2switch/irmind/commit/783da1cc67f0a8867ead3eaf0f1349640132926c) with [reference 3acb485](https://github.com/ns2switch/irmind/commit/3acb485bb56b01a4e19b0e04c659c3f0c0edc4db). Each pair runs sequentially in the same ubuntu-latest job with release optimization and a locked dependency graph. There is one 15 GB repetition per scenario and three at-least-1-GiB repetitions per representative source. Different rows use different runners; compare each row with its own reference.

Both variants stage the 13 distinct public source hashes from the 18 pinned HuntEval episodes and still evaluate all 18 episodes. Private answers stay evaluator-only. The reference receives only the same unique-source staging rule, the 1 GiB test wrapper and the compaction wall clock; its production code is unchanged.

The [complete machine-readable measurements](benchmarks/mapped-pipeline-run.json) retain p50/p95, all host-filter scopes, accumulated phase timers, columns, staging disk, recall and artifact IDs. File SHA-256: cd77071195a4bc38c4eb0fb767b8d65b3c8efff01053ba7685cb5c22569b213c.

### Ingestion and unchanged acceptance gates

Wall time includes corpus generation, ingestion, source verification, signed custody and compaction. The release gate stays 900 seconds for cloud/chronological input and 1,350 seconds for stress. Query failures remain failures even when ingestion passes.

| 15 GB workload | Reference s | Mapped V3 s | Gate s | Candidate result |
| --- | --- | --- | --- | --- |
| Cloud | 957.108 | 1,119.244 | 900 | fail: ingestion |
| Endpoint, stress, 1 host | 1,014.335 | 1,353.894 | 1350 | fail: ingestion |
| Endpoint, stress, 64 hosts | 1,120.537 | 1,493.752 | 1350 | fail: ingestion |
| Endpoint, stress, 1,024 hosts | 1,127.000 | 1,601.401 | 1350 | fail: ingestion |
| Endpoint, stress, 1,025 hosts | 1,041.667 | 1,338.950 | 1350 | pass |
| Endpoint, chronological, 1 host | 606.658 | 781.354 | 900 | fail: query |
| Endpoint, chronological, 64 hosts | 576.336 | 735.422 | 900 | pass |
| Endpoint, chronological, 1,024 hosts | 546.764 | 742.423 | 900 | pass |
| Endpoint, chronological, 1,025 hosts | 549.535 | 751.690 | 900 | pass |

Ingestion passes in 5/9 scenarios; sampled queries pass in 8/9; the combined benchmark passes in 4/9. Of 575 ordinary query samples, 565 return without error and 10 reach the deadline. HuntEval probes and the deliberately expansive path are counted separately.

### Query p95 and errors

Cells show reference → candidate p95 in seconds for the unfiltered queries. Timeout samples are marked as failures, not successful latency measurements. The JSON retains p50, exact error counts and the first/last-host filtered runs.

| 15 GB workload | Term | Entity | Neighbors | Timeline | Path |
| --- | --- | --- | --- | --- | --- |
| Cloud | 4.177 → 3.880 | 5.859 → 9.968 | 0.704 → 0.224 | 0.285 → 0.338 | 0.760 → 0.222 |
| Endpoint, stress, 1 host | 1.253 → 1.456 | 3.777 → 7.946 | 0.382 → 0.121 | 0.069 → 0.169 | 0.355 → 0.119 |
| Endpoint, stress, 64 hosts | 1.538 → 1.900 | 0.443 → 0.788 | 0.050 → 0.055 | 0.065 → 0.224 | 0.051 → 0.054 |
| Endpoint, stress, 1,024 hosts | 1.410 → 1.641 | 0.550 → 0.524 | 0.011 → 0.030 | 0.067 → 0.166 | 0.010 → 0.030 |
| Endpoint, stress, 1,025 hosts | 1.134 → 1.314 | 0.582 → 0.471 | 0.010 → 0.023 | 0.070 → 0.156 | 0.009 → 0.022 |
| Endpoint, chronological, 1 host | 4.554 → 4.839 | 5.204 → timeout (5/5) | 0.561 → 0.171 | 0.461 → 0.457 | 0.500 → 0.177 |
| Endpoint, chronological, 64 hosts | 3.610 → 4.141 | 0.465 → 0.766 | 0.052 → 0.050 | 0.292 → 0.403 | 0.054 → 0.050 |
| Endpoint, chronological, 1,024 hosts | 4.716 → 4.945 | 0.772 → 0.674 | 0.014 → 0.039 | 0.463 → 0.446 | 0.012 → 0.038 |
| Endpoint, chronological, 1,025 hosts | 4.398 → 5.186 | 0.742 → 0.722 | 0.012 → 0.039 | 0.464 → 0.478 | 0.012 → 0.039 |

The deliberate worst-case cloud path retains the existing three-hop/expansion/time limits: both variants report truncation at the 10-second budget. It is separate from the ordinary latency samples and is not a claim of complete path exploration. No query budget, result/sample cap or partial-result marker was relaxed.

### Retained inactive-parent disk

Bytes include all retained inactive V3 parents. Case bytes also include active artifacts and case metadata; optional copied originals are not part of this corpus. Percentages below are calculated from the byte counts and rounded to two decimals.

| 15 GB workload | Inactive bytes | Active bytes | Retained case bytes | Inactive / active | Inactive / case |
| --- | --- | --- | --- | --- | --- |
| Cloud | 6,135,910,385 | 6,522,385,165 | 12,694,870,374 | 94.07% | 48.33% |
| Endpoint, stress, 1 host | 2,995,574,001 | 2,965,277,588 | 5,990,596,509 | 101.02% | 50.00% |
| Endpoint, stress, 64 hosts | 2,875,824,016 | 2,966,572,824 | 5,872,133,544 | 96.94% | 48.97% |
| Endpoint, stress, 1,024 hosts | 2,875,862,669 | 2,965,965,163 | 5,871,998,736 | 96.96% | 48.98% |
| Endpoint, stress, 1,025 hosts | 2,875,862,525 | 2,965,928,470 | 5,872,002,811 | 96.96% | 48.98% |
| Endpoint, chronological, 1 host | 4,922,069,070 | 4,873,908,475 | 9,825,722,465 | 100.99% | 50.09% |
| Endpoint, chronological, 64 hosts | 4,726,692,007 | 4,877,472,867 | 9,633,901,578 | 96.91% | 49.06% |
| Endpoint, chronological, 1,024 hosts | 4,726,767,799 | 4,877,088,217 | 9,634,026,920 | 96.92% | 49.06% |
| Endpoint, chronological, 1,025 hosts | 4,726,768,809 | 4,877,063,371 | 9,634,043,996 | 96.92% | 49.06% |

Every measured ratio exceeds the approximately 20% planning threshold. The separate [inactive-parent retirement proposal](mapped-parent-retirement-design.md) explains an explicit future signed operation and its verification loss. No parent deletion is implemented; V6 still includes every retained file.

### Phase profiles

Stage, sort and replay are accumulated worker timers; replay includes Parquet writing. They can overlap across sources and are not additive wall-time percentages. The legacy conversion/row/Parquet counters are not instrumented on this staged path: zero there does not mean zero work. Compaction is measured separately and is already included in ingestion wall time.

| 15 GB workload | Ref stage/sort/replay s | V3 stage/sort/replay s | Layout ref → V3 s | Peak normalized staging MiB |
| --- | --- | --- | --- | --- |
| Cloud | 1,815.293/0.000/661.088 | 1,622.875/0.000/607.324 | 203.715 → 286.286 | 23.41 |
| Endpoint, stress, 1 host | 422.768/331.540/374.354 | 372.938/452.251/422.443 | 159.748 → 206.162 | 280.19 |
| Endpoint, stress, 64 hosts | 613.399/334.140/462.021 | 519.239/472.386/506.081 | 168.569 → 211.191 | 280.19 |
| Endpoint, stress, 1,024 hosts | 579.739/357.295/447.245 | 492.280/513.744/529.230 | 156.746 → 217.756 | 280.19 |
| Endpoint, stress, 1,025 hosts | 438.320/341.431/391.901 | 379.399/460.526/419.345 | 159.346 → 191.170 | 280.19 |
| Endpoint, chronological, 1 host | 869.892/0.000/301.382 | 883.832/0.000/306.091 | 193.349 → 252.813 | 18.78 |
| Endpoint, chronological, 64 hosts | 829.304/0.000/288.307 | 839.379/0.000/292.767 | 181.729 → 231.574 | 18.78 |
| Endpoint, chronological, 1,024 hosts | 960.917/0.000/329.733 | 939.137/0.000/332.577 | 124.984 → 181.733 | 18.78 |
| Endpoint, chronological, 1,025 hosts | 964.047/0.000/330.702 | 952.007/0.000/336.991 | 126.150 → 183.961 | 18.78 |

The decoder timer excludes its downstream callback. The pure mapper timer is a subset of select/validate/commit/map; do not add it again. Projection and ordered-input commitment have their own timers. Custody wraps the real signer, verifier and atomic append, without replacing them.

| 15 GB workload | Decode s | Pure map s | Select/check/map s | Projection s | Input commit s | Sign/verify/append s |
| --- | --- | --- | --- | --- | --- | --- |
| Cloud | 291.674 | 165.446 | 218.735 | 94.871 | 22.670 | 0.175/0.420/0.930 |
| Endpoint, stress, 1 host | 60.733 | 53.570 | 90.824 | 51.948 | 24.309 | 0.100/0.251/0.648 |
| Endpoint, stress, 64 hosts | 86.437 | 84.343 | 142.432 | 90.356 | 20.437 | 0.120/0.307/0.717 |
| Endpoint, stress, 1,024 hosts | 81.691 | 72.758 | 120.074 | 73.216 | 34.315 | 0.138/0.313/4.125 |
| Endpoint, stress, 1,025 hosts | 61.875 | 54.839 | 92.752 | 52.403 | 24.759 | 0.099/0.256/0.567 |
| Endpoint, chronological, 1 host | 70.810 | 60.141 | 101.293 | 80.079 | 29.339 | 0.143/0.321/2.051 |
| Endpoint, chronological, 64 hosts | 67.981 | 58.121 | 97.733 | 76.874 | 28.148 | 0.136/0.311/1.804 |
| Endpoint, chronological, 1,024 hosts | 92.740 | 82.718 | 133.607 | 97.756 | 28.223 | 0.156/0.374/0.734 |
| Endpoint, chronological, 1,025 hosts | 92.258 | 84.298 | 135.924 | 99.801 | 28.275 | 0.156/0.374/0.781 |

### Three-repetition smoke and correctness

| At least 1 GiB | Reference repetitions s | Mapped repetitions s |
| --- | --- | --- |
| Cloud | 97.081, 95.927, 96.112 | 244.143, 242.878, 243.330 |
| Endpoint, chronological, 64 hosts | 58.906, 57.917, 63.106 | 165.390, 157.180, 156.407 |

All 18 HuntEval episodes retain 19/19 malicious events, 10/10 malicious entities and 14/14 expected path connections per provider, with zero parse errors, in cloud smoke and 15 GB evaluation. These are extraction/search checks, not semantic-mapping or real-model validation.

The new pipeline still misses acceptance gates. Dense entity lookup is a query blocker: mean accumulated cloud entity-scan counters per query rise from 12.190 s to 26.456 s, and normalization from 0.136 s to 4.791 s. For chronological one-host input the corresponding counters are 13.390 → 27.301 s and 0.165 → 5.372 s, with timed-out samples. Each component counter is averaged over five queries. Scan counters accumulate concurrent worker time and include channel backpressure; they are not wall-clock latency or a complete CPU profile. The earlier scoped aggregation counter was not instrumented, so its zero value does not mean zero aggregation cost.

The common writer therefore remains opt-in. Default CLI/TUI/demo writing stays on the historical V2 builder. Fix ingestion overhead and dense scoped-identity lookup before reconsidering default activation; preserve the retained-parent/authentication boundary and every existing query gate. The [ASan summaries](benchmarks/mapped-pipeline-fuzz.json) and the [full code CI](https://github.com/ns2switch/irmind/actions/runs/42514914270) are separate from release-performance acceptance.

## Analyst decision: common-writer default activation

The absolute ingestion targets remain 900 seconds for 15 GB of cloud or chronological endpoint input and 1,350 seconds for stress input. No query may reach its deadline, including the expansive-path check; a time-truncated response does not satisfy this condition. Existing result, sample, hop, expansion, token and scope limits stay unchanged.

Each candidate/reference pair must run in the same release job on the same corpus. Every candidate scenario must take at most 1.10 times its reference ingestion time, and every comparable query p95 must be at most 1.10 times the reference p95. Evaluate the ratios from unrounded timings; rounding cannot turn a failure into a pass.

Default activation requires the relative gate and no query deadline in every scenario. It also requires the absolute gate unless that same scenario's reference misses its absolute target in that same job. Only then can the paired relative gate substitute for the absolute gate. A reference timeout never permits a candidate timeout. Previous combined benchmark pass counts did not evaluate this new relative gate and cannot authorize default activation.

The work order is direct final-file writing, dense entity lookup, then a separate default-activation PR after the complete matrix meets these conditions. Initial direct ingestion must leave zero inactive parents. Later compatible small-file compaction remains available behind a configured count threshold; signed parent retirement remains a [separate future proposal](mapped-parent-retirement-design.md).


## Default V2 regression comparison

The [paired release run](https://github.com/ns2switch/irmind/actions/runs/42537050153)
compares pinned main `3acb485` with `4c2ad5e`. The candidate explicitly disables
the experimental writer. Every pair runs on the same standard runner. All nine
15 GB scenarios and their existing query checks pass on both revisions.

| Scenario | Main ingestion s | Candidate ingestion s | Difference |
| --- | --- | --- | --- |
| cloud-v2 | 819.890 | 831.158 | +1.37% |
| endpoint-v2-1 | 1156.807 | 1168.935 | +1.05% |
| endpoint-v2-1-chronological | 494.383 | 484.602 | -1.98% |
| endpoint-v2-1024 | 1174.504 | 1165.495 | -0.77% |
| endpoint-v2-1024-chronological | 579.211 | 593.446 | +2.46% |
| endpoint-v2-1025 | 1210.280 | 1200.620 | -0.80% |
| endpoint-v2-1025-chronological | 560.336 | 569.788 | +1.69% |
| endpoint-v2-64 | 1017.440 | 1026.372 | +0.88% |
| endpoint-v2-64-chronological | 586.323 | 585.212 | -0.19% |

Derived Parquet byte counts match exactly in every pair; historical physical and
canonical golden tests also pass. Differences range from -1.98% to +2.46% and do
not show a default-writer regression. These are V2 measurements, not evidence
that V3 meets its separate absolute and relative activation gates. The expansive
path result retains the existing bounded truncation behavior and does not waive
the new common-writer no-deadline activation requirement.

The [machine-readable results](benchmarks/default-v2-paired-run.json) include
all query samples' p50/p95 and phase counters. SHA-256: `67c81c065738b87155eda766da568aad80b9a572f2fa431a7b965b9099a66d26`.

## Direct mapped writing: complete paired release matrix

This measurement compares final-file writing with the preceding mapped writer. It does not enable V3.

[Run 42590715429](https://github.com/ns2switch/irmind/actions/runs/42590715429) measured V2 and the preceding mapped writer at `7f1802610e9a635c6123e0ad819ba32229f80ea0`, then direct V3 at `96f238a7bb7b88d7877e92b085ee17f3d040b9d0`. Each scenario uses the same standard Linux runner for its three release stages. Separate scenarios use separate runners; do not infer cross-run speedups.

The measured commits precede the bundled SQLite maintenance update in [PR #210](https://github.com/ns2switch/irmind/pull/210). The later cancellation and portable-fixture corrections do not alter the successful writer path. Composition tests cover the updated dependency, but these timings are evidence for the measured revisions, not a default-activation run of the final composition.

Times include synthetic source generation and ingestion. Endpoint corpora contain 15,676,080,000 bytes. Cloud input size and all scoped query samples are retained in the [allowlisted records](benchmarks/direct-write-run.json).

| Scenario | V2 reference (s) | Previous V3 (s) | Direct V3 (s) | Direct vs previous | Direct vs V2 | Longest standard query p95 (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cloud-v2 | 955.574 | 1121.391 | 609.233 | -45.7% | -36.2% | 9.830 |
| endpoint-v2-1 | 1138.768 | 1561.395 | 1304.080 | -16.5% | +14.5% | 9.266 |
| endpoint-v2-64 | 1032.679 | 1454.647 | 1279.642 | -12.0% | +23.9% | 2.621 |
| endpoint-v2-1024 | 1125.300 | 1531.452 | 1313.879 | -14.2% | +16.8% | 1.710 |
| endpoint-v2-1025 | 1167.178 | 1562.355 | 1334.246 | -14.6% | +14.3% | 1.627 |
| endpoint-v2-1-chronological | 542.718 | 682.466 | 329.727 | -51.7% | -39.2% | 7.255 |
| endpoint-v2-64-chronological | 600.507 | 776.192 | 401.578 | -48.3% | -33.1% | 3.852 |
| endpoint-v2-1024-chronological | 558.144 | 756.079 | 406.778 | -46.2% | -27.1% | 5.166 |
| endpoint-v2-1025-chronological | 596.984 | 789.785 | 368.930 | -53.3% | -38.2% | 4.415 |

All 115 standard query/filter combinations have zero candidate errors, with five samples each. This includes unfiltered, ordinary-host and overflow-host selections. All nine candidate ingestions meet 900 seconds for cloud/chronological data or 1,350 seconds for stress data. The worst-case cloud path is separate: it still returns a time-budget truncation at 10.008 seconds. Standard-query success does not waive that miss.

### Active, parent and temporary disk

GB below means 1,000,000,000 bytes. Derived artifact sizes exclude originals; copying originals is disabled in this synthetic workload. Temporary peaks sample case-local temporary files every 100 ms and are observed lower bounds. The separate logical normalized-staging counters remain in the JSON.

| Scenario | Previous active GB | Direct active GB | Previous inactive parents GB | Direct inactive parents GB | Previous temporary peak GB | Direct temporary peak GB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cloud-v2 | 6.522 | 2.692 | 6.136 | 0.000 | 0.052 | 0.091 |
| endpoint-v2-1 | 2.965 | 1.318 | 2.996 | 0.000 | 0.294 | 0.330 |
| endpoint-v2-64 | 2.967 | 1.319 | 2.876 | 0.000 | 0.294 | 0.325 |
| endpoint-v2-1024 | 2.966 | 1.322 | 2.876 | 0.000 | 0.294 | 0.330 |
| endpoint-v2-1025 | 2.966 | 1.323 | 2.876 | 0.000 | 0.294 | 0.330 |
| endpoint-v2-1-chronological | 4.874 | 2.922 | 4.922 | 0.000 | 0.032 | 0.100 |
| endpoint-v2-64-chronological | 4.877 | 2.925 | 4.727 | 0.000 | 0.032 | 0.099 |
| endpoint-v2-1024-chronological | 4.877 | 2.928 | 4.727 | 0.000 | 0.034 | 0.099 |
| endpoint-v2-1025-chronological | 4.877 | 2.928 | 4.727 | 0.000 | 0.034 | 0.103 |

Initial direct writing retains **zero inactive-parent bytes in every scenario**. Active files also shrink; temporary peaks increase relative to previous V3 in this run. Later explicit maintenance may create retained parents under the existing layout contract. No parent retirement is implemented.

### Representative 1 GiB repetitions

Each representative source runs three repetitions per stage before its 15 GB case. Every smoke input is at least 1 GiB; the table reports median wall time and the full range.

| Source | Stage | Median (s) | Range (s) |
| --- | --- | ---: | --- |
| cloud-v2 | reference | 93.022 | 92.825–94.421 |
| cloud-v2 | baseline | 242.616 | 242.271–242.976 |
| cloud-v2 | candidate | 43.717 | 43.567–44.045 |
| endpoint-v2-64-chronological | reference | 69.787 | 66.846–73.544 |
| endpoint-v2-64-chronological | baseline | 173.270 | 169.701–173.598 |
| endpoint-v2-64-chronological | candidate | 40.197 | 39.450–42.557 |

### Activation result

Direct writing removes initial compaction and its inactive parents and improves all measured ingestion times relative to preceding V3. It remains **opt-in**. Stress ingestion exceeds the paired +10% V2 margin; several query p95 values also exceed that margin, and the worst-case path exhausts its budget. The absolute ingestion results alone are insufficient. Rounded values in this table are descriptive; the separate dense-reader comparison records integer nanoseconds for exact gate evaluation.

The functional suite checks 300 sources with three corrupt files against the clean 297-source collection, signed rejections, bounded exclusions, publication/signing rollback, cancellation, deterministic physical goldens, exact reconstruction, copied-source reconstruction without external originals and public-key-only V6 export verification. Historical goldens remain unchanged.

## Dense mapped entity lookup: exploratory release smoke

For query maintainers, this smoke isolates repeated timestamp formatting and
column binding before another full standard-runner matrix. Both variants use
the mapped pipeline, the same local environment and the same synthetic cloud
corpus: 1,077,079,150 bytes in 1,030 sources. Each query has five samples; this is
one ingestion pair, not a three-repetition or 15 GB acceptance run.

| Query | Before p50 / p95 s | After p50 / p95 s | Errors before / after |
| --- | --- | --- | --- |
| Term | 0.344 / 0.360 | 0.345 / 0.357 | 0 / 0 |
| Entity | 0.312 / 0.317 | 0.177 / 0.179 | 0 / 0 |
| Neighbors | 0.069 / 0.071 | 0.070 / 0.072 | 0 / 0 |
| Timeline | 0.657 / 0.662 | 0.643 / 0.658 | 0 / 0 |
| Path | 0.068 / 0.069 | 0.064 / 0.067 | 0 / 0 |

Entity p95 falls by 43.5% in this smoke. Mean per-query normalization counters
fall from 0.202181 to 0.013884 seconds; accumulated worker scan counters fall
from 0.817129 to 0.493857 seconds. The new scoped aggregation counter is 0.053695
seconds; the earlier implementation did not instrument it. Hash verification
remains mandatory before every file read. Worker counters overlap and include
channel backpressure, so they cannot be summed into wall time.

Per-row RFC 3339 materialization is limited to event-output queries. Count and
scoped-identity queries keep checked physical time columns and still validate the complete input batch,
including rows outside a visitor's result sample. Batch-bound column references
remove repeated schema lookup. Source-order unit checks retain their cross-batch
state and check every hash/offset-mode transition.

Ingestion takes 198.328 versus 185.976 seconds, including layout maintenance;
this query change makes no ingestion speed claim from one pair. Both runs retain
524,160,816 active artifact bytes and 542,250,885 inactive-parent bytes. No parent
is removed, no source/writer recipe changes, and no signed-format golden changes.

The [machine-readable smoke](benchmarks/dense-entity-smoke.json) records exact
source revisions and counters. Its SHA-256 is `847591d4c1c30159e6f35b48eb9fb0fa32f72d08c9651e317c3e453b22960416`.
The complete paired standard-runner matrix below supersedes this exploratory
smoke for the measured revisions, including cloud and chronological one-host
15 GB input. Neither result authorizes default activation or replaces the
absolute and relative gates.

### Exact activation-gate evaluation

Paired release runs also record ingestion and query p95 as integer nanoseconds.
The same test-only instrumentation runs on the pinned reference and candidate;
it does not change production parsing, artifact construction or query limits.
Use `.github/scripts/collect_parquet_pairs.py` in common-schema mode to collect
the complete nine-scenario matrix into `metrics.json`, then run:

```sh
python3 .github/scripts/evaluate_v3_gates.py metrics.json
```

The evaluator rejects incomplete measurements and uses integer comparisons for
the inclusive +10% relative boundary. It keeps the 900-second chronological/cloud
and 1,350-second stress targets. The analyst's paired-reference exception applies
only to the absolute ingestion target; query deadlines are never waived. Its
output is evidence for a separate default-activation decision, and does not enable
an experimental writer.

## Dense mapped entity lookup: complete paired release matrix

This comparison is for query maintainers. [Run 42595706209](https://github.com/ns2switch/irmind/actions/runs/42595706209) measures V2 and direct V3 at `f4139e574971862bb8f08cf0391aacb4db54f0cc`, then the batch-bound reader at `5b4bb1934920fe3d66a91e27c37225237100ba26`. All three stages share the same standard Linux runner within each scenario and use release builds. Compare stages within a row, not different runner instances.

The [complete records](benchmarks/dense-entity-run.json) include exact integer-nanosecond timings, all ordinary/overflow host filters, phase counters, active/parent bytes and temporary peaks. The measured commits precede dependency maintenance in [PR #210](https://github.com/ns2switch/irmind/pull/210); separate composition tests cover the updated dependency. A final default-activation candidate needs evidence for its own composition.

### Unfiltered entity lookup

Each p95 is the maximum of five samples. The previous-reader values include failed requests where shown; a failed request is not a successful latency measurement.

| Scenario | V2 p95 (s) | Previous reader p95 (s) | Candidate p95 (s) | Candidate vs V2 | Previous / candidate errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| cloud-v2 | 5.423 | 9.647 | 5.564 | +2.6% | 0 / 0 |
| endpoint-v2-1 | 5.620 | 10.008 | 4.633 | -17.6% | 5 / 0 |
| endpoint-v2-64 | 0.479 | 0.592 | 0.315 | -34.2% | 0 / 0 |
| endpoint-v2-1024 | 0.805 | 0.157 | 0.156 | -80.6% | 0 / 0 |
| endpoint-v2-1025 | 0.664 | 0.157 | 0.155 | -76.7% | 0 / 0 |
| endpoint-v2-1-chronological | 5.812 | 10.008 | 4.607 | -20.7% | 5 / 0 |
| endpoint-v2-64-chronological | 0.511 | 0.407 | 0.307 | -39.9% | 0 / 0 |
| endpoint-v2-1024-chronological | 0.531 | 0.189 | 0.183 | -65.4% | 0 / 0 |
| endpoint-v2-1025-chronological | 0.507 | 0.170 | 0.166 | -67.3% | 0 / 0 |

The cloud entity p95 falls from 9.647 to 5.564 seconds; its paired V2 result is 5.423 seconds. The unfiltered entity result meets the +10% V2 margin in all nine scenarios. In one-host chronological input the preceding reader fails all five entity samples in both scopes and its cold summary; the candidate has no errors and completes that summary in 3.091 seconds. Entity lookup meets the relative bound in all 23 recorded filter/scenario combinations; other query families still miss it, as shown below.

### Ingestion and retained disk

The reader change does not change the writer recipe. Active artifact byte counts are identical before/after in all nine pairs and inactive-parent bytes remain zero. Ingestion wall time varies slightly; this query change makes no ingestion speedup claim.

| Scenario | V2 reference (s) | Previous reader (s) | Candidate reader (s) | Candidate vs V2 |
| --- | ---: | ---: | ---: | ---: |
| cloud-v2 | 970.862 | 613.712 | 617.718 | -36.4% |
| endpoint-v2-1 | 1032.918 | 1220.264 | 1218.638 | +18.0% |
| endpoint-v2-64 | 1040.126 | 1257.843 | 1266.206 | +21.7% |
| endpoint-v2-1024 | 1033.986 | 1244.795 | 1246.466 | +20.5% |
| endpoint-v2-1025 | 1004.348 | 1221.578 | 1228.482 | +22.3% |
| endpoint-v2-1-chronological | 573.180 | 405.055 | 403.663 | -29.6% |
| endpoint-v2-64-chronological | 600.709 | 425.533 | 430.233 | -28.4% |
| endpoint-v2-1024-chronological | 551.807 | 373.131 | 371.586 | -32.7% |
| endpoint-v2-1025-chronological | 530.552 | 368.957 | 370.984 | -30.1% |

### Exact activation decision

The [machine-readable evaluation](benchmarks/dense-entity-gates.json) reports **eligible: false**. All nine candidate ingestions meet their absolute targets, but stress ingestion misses the paired +10% margin. Every standard query/filter sample completes without an error or time-budget truncation. The separate worst-case cloud path still reaches the ten-second budget; it is included as a failed activation condition.

| Query family | Filter/scenario combinations outside +10% |
| --- | ---: |
| term | 14/23 |
| entity | 0/23 |
| neighbors | 4/23 |
| timeline | 21/23 |
| path | 4/23 |

The relative comparisons use integer nanoseconds, not the rounded table values. Failed performance conditions produce a false decision; missing or malformed evidence is rejected. A reference miss does not waive any candidate query error or deadline. V3 stays opt-in and no sampling, hop, expansion, result, token or time limit changes.

Candidate cold summaries and all 115 standard query/filter combinations complete successfully. Remaining work includes timeline/term materialization cost, stress conversion overhead and the worst-case path. Batch-bound columns retain full temporal validation and every source-unit transition, including rows outside a visitor sample. Per-file hash verification is unchanged.

Three at-least-1-GiB repetitions for cloud and chronological 64-host input are retained for each stage in the raw results. No single smoke repetition replaces the full matrix.

SHA-256 of `dense-entity-run.json`: `972a3ca900dd76bc7a82a223fee056ea8005c8c548eaa8b5670063be5b05d4fb`.
SHA-256 of `dense-entity-gates.json`: `0cf4bf3edec84878aa3a327e24f82605c6062ffcf6441b3dd81dc848dabb0295`.

## Revised analyst activation criteria

This section supersedes the percentage-only activation decision above. Every pair uses the same corpus and release job. A query fails the relative gate only when its candidate p95 is **more than 10% and more than 0.25 seconds slower** than V2. The evaluator compares integer nanoseconds and retains all ordinary query error/deadline checks. It never changes production limits.

The deliberately expansive cloud path remains measured. Its budget truncation is acceptable only when both variants return successfully with the same time-budget and partial-result markers. An unmatched timeout, an error, or a missing partial marker does not qualify. Historical successful metric lines were emitted only after `graph_path(...).unwrap()`; no missing error result is inferred from an absent metric.

| Workload | Absolute ingestion gate | Relative ingestion gate |
| --- | --- | --- |
| Cloud and chronological endpoint, 15 GB | Below 900 seconds | At most +10% versus V2 |
| Disordered endpoint stress, 15 GB | Below 1,350 seconds | Reported; not an activation gate |

The existing [dense-reader matrix](benchmarks/dense-entity-run.json) reevaluated with these rules is still **eligible: false**: 4/9 scenarios pass; 9/9 meet their absolute ingestion target and their ordinary query deadlines. The matched deliberate path is accepted. Remaining relative query regressions are term 7/23 and timeline 8/23; entity, neighbors and ordinary path have none. See the [exact revised evaluation](benchmarks/dense-entity-gates-v2.json), which preserves every failing sample and the original measurements.

A fresh paired matrix on main, including updated SQLite, is required before preparing default activation. V3 remains optional. Separately track stress conversion overhead, delayed materialization of timeline/search results and the expansive cloud path; these items do not prevent independent mapping-family work.

SHA-256 of `dense-entity-gates-v2.json`: `77cb87fcb1c5ce0b93300e4dbe82906c7d78d852981e591e6f88a79d1369a3be`.

## Fresh same-revision V2/V3 matrix with updated SQLite

The [paired release run](https://github.com/ns2switch/irmind/actions/runs/42644089484) uses commit `248200faf8994c95694cfc66d64743538f63e17e` for both variants, including the SQLite update. Each scenario measures V2 and optional mapped V3 on the same standard runner. The [raw allowlisted metrics](benchmarks/main-sqlite-run.json) and [exact gate evaluation](benchmarks/main-sqlite-gates.json) preserve every sample.

**Eligible: false; one of nine scenarios passes all activation gates.** Eight candidate ingestions meet the absolute target; cloud and all four chronological cases also meet the required +10% ingestion bound. The 1,025-host stress case exceeds 1,350 seconds by 13.429 seconds. Its relative difference remains informative, not a gate.

| Scenario | V2 ingestion (s) | V3 ingestion (s) | Absolute ingestion | All activation gates |
| --- | ---: | ---: | --- | --- |
| cloud-v2 | 956.456 | 609.621 | pass | fail |
| endpoint-v2-1 | 1044.182 | 1172.682 | pass | fail |
| endpoint-v2-1-chronological | 730.761 | 484.327 | pass | fail |
| endpoint-v2-1024 | 1129.953 | 1247.546 | pass | fail |
| endpoint-v2-1024-chronological | 563.981 | 407.534 | pass | fail |
| endpoint-v2-1025 | 1220.134 | 1363.429 | fail | fail |
| endpoint-v2-1025-chronological | 512.733 | 332.915 | pass | fail |
| endpoint-v2-64 | 991.327 | 1125.713 | pass | pass |
| endpoint-v2-64-chronological | 577.334 | 433.853 | pass | fail |

Every candidate cold summary and all 115 ordinary query/filter combinations finish without errors or time-budget truncation. The deliberate expansive cloud path returns the accepted matched partial result in both variants. No ordinary deadline, sample, expansion, hop, token or result limit changes.

| Query | Cells failing both +10% and +0.25 s |
| --- | ---: |
| term | 7/23 |
| entity | 5/23 |
| neighbors | 0/23 |
| timeline | 8/23 |
| path | 0/23 |

Cloud entity lookup measures 3.978 s p95 for V2 and 5.530 s for V3. The one-host stress and chronological cases also contribute entity regressions. This same-revision comparison exposes regressions that were absent when compared against the older V2 reference; a phase profile is needed before attributing the difference. Term/timeline materialization and [stress conversion overhead](https://github.com/ns2switch/irmind/issues/186) remain separate performance work.

The recorded absolute misses are the V2 reference cloud run (956.456 s against 900 s) and the V3 1,025-host stress run (1,363.429 s against 1,350 s). Retain both failed samples and all query results; a reference miss does not waive any candidate gate. V3 remains optional for CLI, TUI and demo. No default-activation PR is warranted by these measurements.

SHA-256 of `main-sqlite-run.json`: `130cb5b5af031b2d71bcfb22c3719d271ca39dc7e46630202f784cb354346bd3`.

SHA-256 of `main-sqlite-gates.json`: `3227491547744402b5899ebf6264fc9b4e0e254643726a4d9843b6fadaf8e2f9`.

SHA-256 of `v3-absolute-measurements.json`: `e1ffca20fa465cab0a0e7700d25c2df2366a924c1affdf147a35416180a58640`.

SHA-256 of `v3-absolute-targets.json`: `3b2970d3c48a3ac41c87849da10359212812c70d4392636583756e3376c05e48`.

## Bounded result materialization

Timeline and term-search scans now keep borrowed ordering keys for a bounded batch and allocate owned event payloads only for retained results. Every ordering value is still validated, even when its row lies beyond the result limit. Hash verification, cancellation, stable ordering, deduplication, samples and query deadlines are unchanged. Entity, neighbor and path algorithms are unchanged.

The [release benchmark](https://github.com/ns2switch/irmind/actions/runs/42659581325) compares the previous mapped reader and this change in the same job for each corpus. The [raw allowlisted metrics](benchmarks/result-materialization-run.json) include the older reference only as historical context; the [summary](benchmarks/result-materialization-summary.json) selects the two mapped-reader stages. Every ordinary query completed without errors or deadline truncation in both stages.

| 15 GB corpus | Search p95 before / after | Timeline p95 before / after | Ingest before / after |
| --- | ---: | ---: | ---: |
| cloud | 2.634 / 2.839 s | 0.349 / 0.346 s | 370.666 / 364.764 s |
| endpoint 1 | 1.811 / 1.813 s | 0.204 / 0.203 s | 1309.874 / 1300.277 s |
| endpoint 1 chronological | 4.081 / 4.186 s | 0.532 / 0.532 s | 356.440 / 357.042 s |
| endpoint 1024 | 1.627 / 1.668 s | 0.213 / 0.210 s | 1281.167 / 1286.357 s |
| endpoint 1024 chronological | 3.254 / 3.362 s | 0.523 / 0.525 s | 309.600 / 316.923 s |
| endpoint 1025 | 2.272 / 2.182 s | 0.273 / 0.357 s | 1262.442 / 1252.094 s |
| endpoint 1025 chronological | 4.872 / 4.926 s | 0.680 / 0.680 s | 427.384 / 435.486 s |
| endpoint 64 | 1.711 / 1.861 s | 0.207 / 0.219 s | 1308.666 / 1325.067 s |
| endpoint 64 chronological | 4.815 / 4.744 s | 0.786 / 0.484 s | 417.762 / 418.981 s |

The largest 15 GB timeline improvement is the chronological 64-host sample: 0.786 to 0.484 seconds (38.4%). Cloud timeline is effectively unchanged at 0.349 to 0.346 seconds. Improvements are workload-dependent: the 1,025-host disordered timeline increases from 0.273 to 0.357 seconds, and most term-search samples remain limited by file hashing and scanning rather than result allocation. These measurements do not claim a general throughput improvement.

A synthetic unit test additionally counts materialized rows: a 4,096-row batch with a result limit of ten owns only ten new result payloads, while malformed nonselected ordering values still fail validation. This is a deterministic allocation check, not a release throughput measurement.

Metric file checksums (SHA-256):

- `result-materialization-run.json`: `08aa2903ff59b5ef7d884daee977e27c64ce86f099fe0dfe6b7ce2773479d6d2`.
- `result-materialization-summary.json`: `82584fefe79de9d93ea74a899db598fecff7d2a9e7274c39b890bb3785e4ae17`.


## ECS source pipeline: paired release smoke

The separate ECS source decoder and native mapping were measured in one local
release execution, with three paired repetitions per pipeline. Each ingested the
same 1,073,742,930-byte synthetic NDJSON file: 917,729 chronological events, one
host, explicit authentication failures and 900 bytes of padding per event. Every
run retained all events, rejected none and verified the signed chain. This is a
1 GiB smoke measurement, not a new 15 GB release-gate result.

| Pipeline | Repetition 1 (s) | Repetition 2 (s) | Repetition 3 (s) | Median (s) | Median MiB/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| Existing V2 extraction | 25.168 | 23.098 | 23.493 | 23.493 | 43.588 |
| Source decoder + native ECS mapping, V3 | 30.713 | 33.611 | 30.673 | 30.713 | 33.341 |

The mapped pipeline takes 30.7% longer at the median. It performs explicit typed
classification and role validation and writes the common schemas; this is not
an isolated parser-speed comparison. The default route and its golden bytes are
unchanged during decoder rollout. No performance threshold is relaxed.

Timing covers ingestion; corpus creation, physical-row accounting and signed
verification occur outside the timed region. The sample commitment uses the same
64 KiB prefix as normal ingestion. The [machine-readable measurements](benchmarks/ecs-source-smoke.json)
record the implementation commit and the identical source SHA-256 for all runs.

Reproduce from the repository root with `sh .github/scripts/benchmark_source_pipeline.sh`.

## EVTX and ECS: shared source-pipeline smoke

For contributors investigating decode/map overhead, this release measurement compares
three paired 1 GiB ingestions per source on one `ubuntu-24.04` runner. Both variants
use the same generated file, native helper and normal custody checks. The EVTX
fixture contains 278,528 records across the supported Security IDs; ECS contains
917,729 records. Every ingestion verifies its event count, zero rejections and the
signed chain. These smokes do not replace the full 15 GB matrix.

[Workflow run](https://github.com/ns2switch/irmind/actions/runs/42813786675) ·
[Complete measurements](benchmarks/evtx-ecs-shared-source-profile.json).

| Source | V2 median | Mapped median | Difference |
| --- | ---: | ---: | ---: |
| EVTX | 13.358 s | 22.333 s | +67.20% |
| ECS | 31.578 s | 41.555 s | +31.59% |

The same diagnostic harness then runs additional source-decoder/mapping passes.
It preserves the mapping manifests, output and source commitments; a shared
contract checks that instrumentation does not change the result. These are wall
intervals, not CPU samples. They exclude Parquet writing and signed custody. The
diagnostic tuple file uses unbuffered writes; production ingestion already buffers
those writes. Its shared-boundary interval therefore must not be presented as the
production validation cost or added to the full-ingestion totals.

| Standalone phase, median | EVTX | ECS |
| --- | ---: | ---: |
| Decoder/IPC, excluding callback | 3.429 s | 5.414 s |
| Selected mapper | 1.556 s | 13.539 s |
| Shared validation, selection, source hash and diagnostic tuple writes | 1.195 s | 3.162 s |
| Source commitment finalization | 0.619 s | 2.045 s |

A 20,000-iteration micro-measurement uses one decoded source record from each
corpus. It times clone/drop, bounded validation and JSON rendering separately.
These values are diagnostics for those representative records, not allocator
counts or evidence that every record has the same cost.

| Operation, median microseconds per iteration | EVTX | ECS |
| --- | ---: | ---: |
| Clone/drop decoded source tree | 1.061 | 0.889 |
| Validate decoded fields | 0.081 | 0.076 |
| Validate and render decoded fields | 1.099 | 1.593 |

The measured mapper cost differs substantially between the sources. The data does
not establish a single parser bottleneck, and the small validation micro-time does
not justify weakening checks. Code inspection identifies shared opportunities:
move a validated projection into the writer instead of cloning its text and
entities, retain one rendered source buffer where possible, and buffer the tuple
reads used by commitment finalization. The ECS compatibility projection also
clones its original field tree before rendering. Measure these changes on the full
ingestion path with the same corpus and runner; preserve every origin, taint,
validation, hash, signature and canonical byte check. No optimization is applied
by this measurement.

Reproduce with the manual graph-benchmark workflow's `evtx_source` input. It runs
both paired release smokes and the shared counters; no provider or model is used.

## Production source pipeline: shared allocation work

The [paired release run](https://github.com/ns2switch/irmind/actions/runs/42858498451)
compares profiling-only `7df7050` with optimized `f455a5c` in the same
`ubuntu-24.04` job. Each source has three V2/V3 pairs before and after the change,
at least 1 GiB of synthetic input, actual source hashing, Parquet publication and
signed custody. Every ingestion checks the complete event count, zero rejected
records and the chain. EVTX uses the isolated helper. Linux is journald extraction;
EVTX, ECS and CloudTrail use their independent classification mappings.

Both builds use the same optimized release settings, full debug symbols and frame
pointers. Timing runs do **not** run under Heaptrack. Separate V3 runs count calls
to allocation functions; at least 99.64% are attributed to production phases.
First-party crates are rebuilt between worktrees; external dependencies are shared.
See the [method](source-pipeline-profiling.md), [exact summary](benchmark-data/common-pipeline-f455a5c/summary.json)
and [run metadata](benchmark-data/common-pipeline-f455a5c/metadata.json).

Median wall time in seconds:

| Source | V2 before | V3 before | V2 after | V3 after | V3 improvement | V3 overhead vs V2 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| EVTX | 17.718 | 28.550 | 17.741 | 27.461 | 3.81% | +54.78% |
| ECS | 40.133 | 55.256 | 39.942 | 50.471 | 8.66% | +26.36% |
| CloudTrail | 24.363 | 54.108 | 23.947 | 49.725 | 8.10% | +107.65% |
| Linux / journald | 32.650 | 31.692 | 32.633 | 29.036 | 8.38% | -11.02% |

The unchanged V2 reference varies by at most 1.71%. The orienting 15% typed-pipeline
overhead target is met only by journald. This result does not meet that target
for EVTX, ECS or CloudTrail and is not a reason to remove validation or limits.

Allocation calls, including explicitly reported outside/unattributed calls:

| Source | Before | After | Reduction | Commitment finalization before → after |
| --- | ---: | ---: | ---: | ---: |
| EVTX | 171,033,237 | 158,679,710 | 7.22% | 278,554 → 27 |
| ECS | 368,008,547 | 314,184,560 | 14.63% | 912,278 → 8 |
| CloudTrail | 371,933,729 | 334,045,831 | 10.19% | 757,765 → 8 |
| Linux / journald | 160,560,211 | 156,718,557 | 2.39% | 960,421 → 8 |

The buffer and reused tuple remove almost all per-record finalization allocations.
Moving checked projections and reusing JSON string serialization reduce mapping
allocations from 144.14 to 93.96 million for ECS and 81.84 to 46.98 million for
CloudTrail. Current format goldens are unchanged.

Candidate median timing counters, in seconds:

| Source | Decoder exclusive | Pure mapping | Validation / selection / tuple spool | Writer projection | Finalize commitment | Row / Arrow batches | Parquet writing |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| EVTX | 6.588 | 3.380 | 1.930 | 7.801 | 0.048 | 4.415 | 15.931 |
| ECS | 6.501 | 20.859 | 2.860 | 12.258 | 0.153 | 2.874 | 5.839 |
| CloudTrail | 14.285 | 11.077 | 2.787 | 13.820 | 0.128 | 3.699 | 6.925 |
| Linux / journald | 8.665 | 4.762 | 3.200 | 5.139 | 0.160 | 3.359 | 5.521 |

These intervals overlap and can include work in parallel workers; **do not sum
them or turn them into disjoint wall-time percentages**. Allocation attribution
uses the deepest recognized frame and is exclusive. Per-phase counts are in the
`*-allocations.json` files alongside the summary, with raw timing counters in
`*-timings.txt`. Raw Heaptrack captures and filesystem paths are not published.

The remaining measured cost is concentrated in pure mapping and checked writer
projection for ECS, decoding and projection for CloudTrail, and Parquet writing
plus projection for EVTX. The typed route also retains classifications, occurrence
roles and provenance that V2 does not compute. Observed active artifact sizes are
88.05/67.97 MB (V3/V2) for EVTX, 163.01/51.43 MB for ECS, 161.68/54.86 MB for
CloudTrail and 85.31/69.53 MB for journald. EVTX has 149 active files, compared with
three in its V2 reference. These layout differences are observations, not an
isolated causal experiment. The synthetic padding is compressible; these smokes
do not replace the full 15 GB matrix. The source-pipeline rollout continues with
these remaining costs documented, without changing the absolute performance gates.

### OCSF source decoder and mapping smoke

The production-path [release run](https://github.com/ns2switch/irmind/actions/runs/42875425300)
compares three paired 1 GiB OCSF JSON ingestions on one `ubuntu-24.04` runner,
with matching source hashes, 903,824 accepted records per ingestion, no rejects,
and verified signed custody. No model or remote service is involved. Timings
exclude Heaptrack; allocation counts come from a separate instrumented V3 run.
The measured revision is `585a8c12e691679298023b760d577c2493e18295`.

| Route | Median ingestion | Throughput | Typed overhead |
| --- | ---: | ---: | ---: |
| V2 reference | 40.321 s | 25.40 MiB/s | — |
| Source decoder → OCSF mapping → V3 | 45.966 s | 22.28 MiB/s | +14.0% |

Median V3 counters identify 7.300 s in source decoding, 14.761 s in mapping,
and 12.693 s in writer projection. These nested/worker timing counters are not
an additive wall-time breakdown. The native mapping validates original OCSF
class/category, activity/status and typed fields; the reference does not perform
that common-event interpretation. This compressible synthetic smoke is not a
substitute for the full 15 GB matrix. [Raw counters and allocation attribution](benchmark-data/ocsf-source-585a8c1/metadata.json)
are retained with the run metadata.

### Adaptive source and query workers

The [same-runner release sweep](https://github.com/ns2switch/irmind/actions/runs/42920654601) used four logical CPUs and 1,077,079,150 bytes of synthetic CloudTrail across 1,030 files. Both revisions wrote mapped V3, with identical output size (259,162,335 bytes). Peak RSS covers the benchmark process, including queries; it excludes compilation.

| Scheduling | Ingest wall (s) | Speedup over one worker | Peak RSS (MiB) | Slowest query p95 (s) |
| --- | ---: | ---: | ---: | ---: |
| Fixed four workers, reference | 44.460 | 1.49× | 133.0 | 0.399 |
| Adaptive, cap one | 66.312 | 1.00× | 89.2 | 0.829 |
| Adaptive, automatic (three) | 48.146 | 1.38× | 100.7 | 0.442 |
| Adaptive, cap four (all CPUs) | 44.391 | 1.49× | 109.9 | 0.389 |

One run per setting. The four-worker cap matched the fixed reference's elapsed time. Automatic mode took 8.3% longer while leaving a logical CPU available. This sweep measures scheduling across files, not decoding a single large file.

### Record workers in a single source

The [release sweep on one four-CPU Linux runner](https://github.com/ns2switch/irmind/actions/runs/42927078536) ingested one 1 GiB NDJSON file (663,212 records). All settings wrote 48,510,482 bytes of mapped V3 artifacts.

| Scheduling | Ingest wall (s) | Peak RSS (MiB) |
| --- | ---: | ---: |
| Reference, sequential record decoder | 20.091 | 72.4 |
| Candidate, one worker | 19.390 | 64.7 |
| Candidate, automatic (three) | 19.257 | 72.6 |
| Candidate, four workers | 18.898 | 72.2 |

Four workers were 5.9% faster than the reference and 2.5% faster than one worker in the candidate. These are single runs. The result includes hashing, mapping, Parquet, and signed custody, so it does not isolate decoding throughput.

The [isolated EVTX trial](https://github.com/ns2switch/irmind/actions/runs/42926652010) used a single 1 GiB synthetic source with 1,048,576 records. It compared the same native broker path and V2 test writer on each runner. The process and helper peaks are separate, not summed.

| System | Helper worker setting | Ingest (s) | Parent / helper peak (MiB) |
| --- | --- | ---: | ---: |
| Linux | One (unchanged) | 36.17 | 289.1 / 3.4 |
| macOS | One | 49.90 | 183.2 / 7.6 |
| macOS | Cap four | 49.64 | 182.9 / 8.0 |
| macOS | All available, within the cap | 47.79 | 182.7 / 8.1 |
| Windows | One | 78.49 | 155.9 / 6.1 |
| Windows | Cap four | 89.28 | 156.6 / 6.9 |
| Windows | All available, within the cap | 87.19 | 157.1 / 6.9 |

No limits were reached. Every Windows run used one network witness. The trial preserved frame bytes and passed the native containment tests. The Windows regression and the small macOS difference do not justify enabling the trial for shipped helpers. Linux remains sequential under its existing seccomp policy.

The [four-CPU Windows release sweep](https://github.com/ns2switch/irmind/actions/runs/42929482449) used a single 4 GiB NDJSON file (2,652,851 records). Each run passed normal disk preflight, verified the artifacts, and wrote 194,200,266 artifact bytes.

| Scheduling | Ingest wall (s) | Peak working set (MiB) |
| --- | ---: | ---: |
| Reference, sequential record decoder | 94.292 | 65.5 |
| Candidate, one worker | 90.144 | 66.7 |
| Candidate, automatic (three) | 86.635 | 66.4 |
| Candidate, four workers | 87.076 | 70.9 |

Four workers reduced wall time by 7.7% against the reference. Automatic and four-worker runs differ by less than half a second in this sweep; this does not establish a ranking.

### Parallel completion of independent partition writers

The [paired endpoint release sweep](https://github.com/ns2switch/irmind/actions/runs/42928749774) used 1,076,450,200 bytes of chronological input on four logical CPUs. It moved final row-group compression, sync and hashing to bounded workers after file boundaries were fixed. Appends and eviction still follow the original recipe.

| Scheduling | Ingest wall (s) | Peak RSS (MiB) | Slowest query p95 (s) |
| --- | ---: | ---: | ---: |
| Reference, four workers | 39.516 | 278.2 | 0.426 |
| Candidate, one worker | 55.753 | 250.7 | 1.053 |
| Candidate, automatic (three) | 42.883 | 266.6 | 0.543 |
| Candidate, four workers | 38.712 | 273.7 | 0.424 |

All settings wrote 196,741,347 artifact bytes. The four-worker candidate was 2.0% faster than the same-runner reference. Candidate finalization took 0.639 s at one worker and 0.293 s at four. Single runs per setting; the result does not establish an improvement for every partition distribution.

### Bounded queues when a group contains disordered sources

The [paired release sweep](https://github.com/ns2switch/irmind/actions/runs/42933264116)
used four logical CPUs and 515 disordered synthetic endpoint files (1,076,424,160
bytes, 64 hosts). All settings wrote 160,699,746 bytes of mapped V3 artifacts,
including 24,366,105 bytes of co-observations. This corpus exercises the sort
fallback for every source. Separate mixed-order tests check that ordered
sources do not create normalized spools during fallback.

| Scheduling | Ingest wall (s) | Peak RSS (MiB) | Sampled staging peak (bytes) | Slowest query p95 (s) |
| --- | ---: | ---: | ---: | ---: |
| Reference, four workers | 100.502 | 259.1 | 71,026,983 | 0.600 |
| Candidate, one worker | 108.881 | 257.4 | 50,686,719 | 1.723 |
| Candidate, automatic (three) | 96.088 | 273.3 | 63,757,281 | 0.752 |
| Candidate, four workers | 92.743 | 278.7 | 70,396,245 | 0.622 |

The four-worker candidate took 7.7% less wall time than its reference and
14.8% less than the one-worker candidate. Peak RSS was 19.7 MiB higher than
the reference. Staging was sampled every 100 ms; compilation is outside the
measurement. An [earlier variant](https://github.com/ns2switch/irmind/actions/runs/42930749194)
without the bounded prefix replayed the decoder at the first order break and
took 95.952 s versus its own reference's 92.659 s. Both are single sweeps on
separate runners; compare the pairs, not the absolute times between jobs.

### NDJSON source framing in the sole-writer rollout

The [1 GiB Linux sweep](https://github.com/ns2switch/irmind/actions/runs/42989218819) and [4 GiB Windows sweep](https://github.com/ns2switch/irmind/actions/runs/42985241365) each compare reference and candidate on the same four-CPU runner. The reference already includes record workers and parallel partition completion. Candidate `8fcd563f597bf829ae445724bd483fccf3d88015` retains the existing physical recipe and decodes complete NDJSON frames with their logical source offsets.

| Input / runner | Setting | Ingest wall (s) | Peak process memory (MiB) |
| --- | --- | ---: | ---: |
| 1 GiB / Linux | Reference, four | 16.355 | 94.8 |
| 1 GiB / Linux | One worker | 16.912 | 86.4 |
| 1 GiB / Linux | Automatic, three | 15.075 | 87.5 |
| 1 GiB / Linux | 4 workers | 14.593 | 94.1 |
| 4 GiB / Windows | Reference, four | 83.463 | 78.6 |
| 4 GiB / Windows | One worker | 94.130 | 66.6 |
| 4 GiB / Windows | Automatic, three | 85.333 | 72.8 |
| 4 GiB / Windows | 4 workers | 80.974 | 80.7 |

At four workers, the candidate reduced ingestion by 10.8% on the 1 GiB workload and 3.0% on the 4 GiB workload relative to its same-runner reference. All settings accepted 663,212 / 2,652,851 records and wrote 48,510,482 / 194,200,266 artifact bytes respectively. Each setting has one measurement. Ingestion timing excludes input generation and subsequent verification; peak memory covers the complete benchmark process. The [machine-readable results](benchmark-data/current-ndjson-workers.json) retain the commits and exact counters. Worker-count tests separately compare complete artifact hashes and signed chains from the same initial case and clock.


Disordered mapped groups sort independent source spools concurrently under the same adaptive worker cap. Space reservation covers every active sort; each sort retains its row-count, byte-count and hash checks. The coordinator still consumes sources in canonical order and assigns all partitions and physical file boundaries. Parallel completion remains enabled after those boundaries have been fixed.

### Independent source sorts under the shared worker budget

The [paired release sweep](https://github.com/ns2switch/irmind/actions/runs/43000350075)
compares `a10ec39` with `8fcd563` on the same four-CPU runner. The input is
515 disordered endpoint files, 1,076,424,160 bytes and 64 hosts. Both versions
retain sequential canonical appends and parallel partition completion.

| Setting | Ingest wall (s) | Peak RSS (MiB) | Sampled staging peak (bytes) |
| --- | ---: | ---: | ---: |
| Reference, four | 98.847 | 280.6 | 58,917,110 |
| Candidate, one | 117.676 | 251.4 | 40,225,561 |
| Candidate, automatic (three) | 80.254 | 270.9 | 58,662,648 |
| Candidate, four | 72.581 | 280.2 | 78,216,864 |

Four workers reduced ingestion by 26.6% against the paired reference; the
candidate's one-to-four-worker speedup was 1.62 times. All settings wrote
160,699,746 artifact bytes, including 24,366,105 co-observation bytes. These are
single measurements; sampled staging and process high-water RSS cover the whole
benchmark, while ingestion excludes generation and subsequent verification.
[Exact counters and commits](benchmark-data/current-source-sort-workers.json)
are available separately. The older phase timer does not isolate independent
sort time, so its zero sort counter is not a measured absence of sorting.

The [preceding full 15 GB matrix](https://github.com/ns2switch/irmind/actions/runs/42990643490)
used `8fcd563`, before independent sorts were parallelized:

| Corpus | Hosts | Ingest wall (s) | Absolute target (s) | Result |
| --- | ---: | ---: | ---: | --- |
| Cloud | — | 506.504 | 900 | Pass |
| Endpoint chronological | 1 | 424.240 | 900 | Pass |
| Endpoint chronological | 64 | 424.839 | 900 | Pass |
| Endpoint chronological | 1,024 | 318.693 | 900 | Pass |
| Endpoint chronological | 1,025 | 510.431 | 900 | Pass |
| Endpoint stress | 1 | 1,363.082 | 1,350 | Fail |
| Endpoint stress | 64 | 1,410.313 | 1,350 | Fail |
| Endpoint stress | 1,024 | 1,295.413 | 1,350 | Pass |
| Endpoint stress | 1,025 | 1,294.628 | 1,350 | Pass; tracked exception remains |

All ordinary queries completed within their deadline. The deliberate worst-case
cloud path retained its partial-result marker at the budget. HuntEval checks
found all expected events, entities and paths in each provider. This matrix does
not establish the candidate's 15 GB performance; its full rerun remains required.
[Machine-readable measurements](benchmark-data/current-v3-15gb-before-sort.json)
include per-query counters and the recorded phases. Scenario names containing
`v2` identify the frozen input generator; the writer in this run was mapped V3.

### Complete mapped matrix with parallel independent source sorts

The [nine-scenario release matrix](https://github.com/ns2switch/irmind/actions/runs/43004608708)
uses source commit `1bbc380`, canonical sequential appends and bounded parallel
completion. Independent disordered source sorts use the same adaptive worker
budget. All absolute targets pass. Each scenario is one release measurement on
Ubuntu 24.04; comparisons with earlier workflow runs are not paired speedups.
The paired 1 GiB sorting sweep above isolates that change on one runner.

| Corpus | Hosts | Ingest wall (s) | Target (s) | Largest ordinary query p95 (s) |
| --- | ---: | ---: | ---: | ---: |
| Cloud | — | 609.711 | 900 | 6.235 |
| Endpoint chronological | 1 | 340.235 | 900 | 3.923 |
| Endpoint chronological | 64 | 354.495 | 900 | 3.661 |
| Endpoint chronological | 1024 | 382.213 | 900 | 4.850 |
| Endpoint chronological | 1025 | 489.929 | 900 | 6.435 |
| Endpoint stress | 1 | 1,046.624 | 1,350 | 4.879 |
| Endpoint stress | 64 | 997.701 | 1,350 | 2.652 |
| Endpoint stress | 1024 | 1,055.029 | 1,350 | 1.927 |
| Endpoint stress | 1025 | 989.384 | 1,350 | 2.457 |

All ordinary queries report zero errors and zero time-budget hits. The deliberate
worst-case cloud path retains its approved partial-result marker at the budget;
it is measured separately from ordinary queries. Initial ingestion retains zero
inactive-parent bytes in every scenario. HuntEval checks retain full event,
entity and path recall with no parse errors for all three providers.

Normalized staging peaks at 426,393,546 bytes (sampled), below the active group's
reserved disk budget; this is not a process RSS measurement. The source inputs
are 15,685,641,524 bytes for cloud and about 15,676,080,000 bytes for endpoint.
[Exact measurements](benchmark-data/current-v3-15gb-parallel-sort.json) include
phase counters, source and artifact sizes, ordinary and overflow query samples,
HuntEval recall and the separate worst-case path. A zero legacy sort counter in
this run does not measure the sort phase; later instrumentation times the actual
per-source sorts. Scenario names containing `v2` identify the frozen input
generator. Every scenario here uses direct mapped V3.

### Current mapped EVTX: one 1 GiB file

The [native worker sweep](https://github.com/ns2switch/irmind/actions/runs/43011292588)
uses the production source decoder, identified mapping, direct V3 writer and
signed ingestion. Each input contains 1,048,576 synthetic records in
1,073,745,920 bytes. The contained EVTX helper remains sequential. Worker caps
control the main pipeline; these measurements do not establish parallel EVTX
decoding. Each setting is one release measurement on the same four-core runner
per operating system. Automatic selection uses three workers; four is all cores.

| System | Worker cap | Ingest (s) | MiB/s | Main peak MiB | Helper peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Linux | 1 | 27.712 | 36.95 | 84.56 | 3.17 |
| Linux | 4 | 27.495 | 37.24 | 83.65 | 3.14 |
| Linux | None | 27.373 | 37.41 | 80.42 | 3.23 |
| Windows | 1 | 37.670 | 27.18 | 68.65 | 5.99 |
| Windows | 4 | 35.251 | 29.05 | 66.03 | 6.02 |
| Windows | None | 37.471 | 27.33 | 69.52 | 6.03 |

Every source is accepted completely and all limits remain unchanged. Final full
verification passes and is timed separately. Windows performs exactly one
network witness per session. Peak memory samples the OS process high-water
counters every 20 ms and includes generation and verification; ingestion wall
time excludes those phases. Small differences between settings are single-run
observations, not evidence of helper scaling.
[Machine-readable results](benchmark-data/current-mapped-evtx-workers.json).
