# Artifact V2 partitions: step (c) report

This report is for the analyst reviewing [PR #170](https://github.com/ns2switch/irmind/pull/170). It covers generic partitions and the approved JSON compatibility correction. Migration/export V5 and release-scale benchmarks remain separate steps.

## 1. Summary

Step (c) implements the [approved partition contracts](../parquet-v2-partition-contracts.md) and source-aware replay. Normalization, deterministic allocation, bounded staging/sorting, overflow and checked host queries share the existing custody path. The release audit permits retaining `json-stream-v2`: its fast path now explicitly reproduces released lexical bytes. Default CLI/TUI sessions still write V1 until step (d) integrates migration/export V5.

## 2. Milestones

| Milestone | Change and evidence |
| --- | --- |
| H0 | Existing dependency-direction and quality gates retained; release JSON isolation gate added. |
| H1 | Checked host selectors, unchanged signed encodings, shared stable event ordering. |
| H2 | Approved additive batch/profile and source-aware callbacks; native mixed-parser replay tested. |
| H3 | No guard bypass or new untrusted-to-model route; invalid filters fail closed. |
| H4 | Signed history controls allocation; explicit migration required to change a source generation. |
| H5 | Existing analyst acceptance unchanged; no provider or default configuration changes. |
| H6 | Existing graph commands accept the checked host field; no new presentation use case. |
| H7 | Generic V2 partition enhancement implemented; release-scale host/default measurements remain step (e). |
| H8 | Existing modules retained; no remote connector or credential added. |

## 3. Structure

Application contracts own the closed profiles, checked batch and signed-source router. Parser modules declare their own capabilities. Infra owns private normalization, staging, bounded external ordering, allocation, segment consolidation and scans in real modules. No adapter depends on another adapter. The ordinary suite includes the dependency-direction test.

## 4. Types and ports

The analyst approved `LargeCaseStore::prepare_local_batch`, `LocalBatchRequest`, `PartitionLimits`, optional `StreamingEventParser::partition_profile`, its source-aware optional companion, and `GraphQueryFilter::parse_with_host`/`host`. Existing methods keep their signatures. Unknown replay sources are errors, with no mutable last-source routing state. No further port expansion is introduced here.

## 5. Compatibility decisions

The [audit](../release-json-feature-audit.json) checks **23 exact locked release target graphs** from v0.1.0 through v0.1.5; none enabled `serde_json/preserve_order`. The AWS SDK's development-only HTTP test utility activates it in workspace tests. Following the analyst's decision, `json-stream-v2` remains lexical on every path. No insertion reader or new parser version is created. Unsupported development artifacts that depended on insertion order fail reconstruction against their signed hashes.

The new physical-byte regression is retained. No pre-existing fixture/golden is modified. The date-only precise builder keeps its historical mapping and flush behavior; generic partitions use their own builder revision. Source aliases cannot silently switch builder/parser generation. [Full evidence and parser audit](../json-line-order-compatibility.md).

## 6. Security

Normalization derives its policy ID from `unicode_normalization::UNICODE_VERSION`; a test pins Unicode 18.0.0 and the approved identifier. Input/output expansion is bounded. Invalid source values use typed overflow and keep actual values. Host arguments reject paths, controls and overflow impersonation, cannot exceed either scope ceiling and never become an absent filter on failure. Exact matching includes overflow, normalization collisions and legacy rows. Selected Parquet files are hash-verified. Existing query sampling, expansion, result and time limits remain intact. Overflow summaries count signed event files, not an inferred percentage of events.

## 7. Storage and signatures

At most four normalized sources are staged privately below the case spool. Preflight reserves 16 times each input plus 64 MiB per source and another 64 MiB margin; writes cannot exceed the reservation. Only out-of-order sources require external sorting. Sorting preflights another twice the largest staged stream plus 64 MiB, uses bounded chunks, two readers and at most 64 run levels. Every intermediate stream is hash/size/count checked. Cancellation checks remain between rows and batches.

A bounded 16-partition writer pool flushes at the byte budget and consolidates revisited segments. RAII removes temporary files on success/error/cancellation. Case-open recovery removes owned orphaned normalized/reconstruction workspaces and rejects symlink substitutes. Allocations are derived only from verified signed history and canonical source/record order; cancelled work consumes no signed slots. Tests cover native interleaved Linux audit completion, cancellation/retry and generation aliases.

The profiler tracks logical overlapping normalized/sort/segment/merge bytes. **The actual 15 GB temporary-disk peak has not been measured in this PR**; it must be reported with release benchmarks in step (e). Host starts at 64, with the unchanged hard ceiling of 1,024; measurement decides the final default.

## 8. Quality

| Check | Local result |
| --- | --- |
| rustfmt and workspace/all-features/all-targets Clippy `-D warnings` | Passed. |
| Complete workspace suite including demo PTYs | **537 passed, 0 failed, 8 existing manual/benchmark skips**, 442.116 s; includes all demo PTYs. The subsequently added V1 physical-hash assertion also passes in both final format runs. |
| Explicit preserve-order format suite | **20 passed, 0 failed**, 1.569 s; the same 20 pass without the feature in 1.380 s. Includes the pre-fix released-graph V1 physical-hash assertion. |
| JSON module with explicit preserve-order | 18 passed, including nested/raw wrappers, arrays and capped extraction. |
| Release-gate unit checks | 3 passed; the current normal/build graphs also pass the actual guard. |
| Cargo-deny | Advisories, bans, licenses and sources pass; existing duplicate warnings remain. |
| Documentation checks | Pass, with the pre-existing stale `SECURITY.es.md` warning. |

The explicit alternate-feature job runs NDJSON and single-object routes and dedicated historical-byte tests for ECS, OCSF, Velociraptor, Chainsaw, plaso, journald and declarative JSON. Zeek and Suricata modules are absent from this workspace, so no coverage is claimed for them. Final remote CI and merge evidence belong to the PR's checks and completion comment; an older green commit does not validate newer code.

## 9. External dependencies

The sole direct production edge added by partitions is the already approved `unicode-normalization =0.1.26` for NFKC; it was already locked through security. Workspace packages remain **565 → 565**, fuzz workspace **308 → 308**. This JSON correction adds no package. No new unsafe block, network client or credential is introduced. AWS test utilities remain development-only; every release build job rejects a shipped `preserve_order` feature.

## 10. Debt and remaining work

No new fuzzing or 15 GB performance result is claimed here. Legacy host joins keep bounded batches and the existing deadline; their cost belongs to mixed-case benchmarks. Step (d) must add explicit open-case migration/export V5 before enabling default V2 writing. Step (e) must measure disk peaks, cloud/endpoint/network host cardinalities and query latency, retaining the hard caps. No control is relaxed for a test.

## 11. Decisions and blockers

The source-aware callback and release-only lexical JSON reconstruction decisions are approved and implemented. No further analyst decision is requested for this correction. Merge requires green checks on the current PR head and a green main run afterward, following the normal process. Any future departure from the approved migration or signed envelope still requires prior review.

## 12. Next step

Integrate step (c) only after current-head CI passes. Then implement explicit open-case migration/export V5 in its own PR and release benchmarks in the following PR. Keep V1 as the default writer until both (c) and (d) are integrated.
