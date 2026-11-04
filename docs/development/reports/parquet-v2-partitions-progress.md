# Artifact V2 partitions: implementation review checkpoint

This report is for the analyst reviewing step (c). This is an unfinished draft, not a completion or merge request.

## 1. Summary

The approved contract document is merged in [PR #169](https://github.com/ns2switch/irmind/pull/169). [Main CI passed](https://github.com/ns2switch/irmind/actions/runs/41787683760). Step (c) has a separately tested implementation draft. Mixed-parser reconstruction needs the small source-aware optional callback described below. Production CLI/TUI writing remains V1; migration/export V5 and release benchmarks are not implemented here.

## 2. Milestones

| Milestone | State relevant to this change | Completion evidence |
| --- | --- | --- |
| H0 | Existing gates retained | Dependency direction is part of the passing local suite. |
| H1 | Additive checked host selector | Invalid values and both scope ceilings tested; existing wire goldens pass. |
| H2 | Approved batch/profile additions drafted | Local/object ingestion share preparation; source-bound replay pending approval. |
| H3 | Existing guard retained | No new path sends parsed or indexed text directly to the model. |
| H4 | Existing custody retained | Existing source, audit, signature and seal encodings unchanged. |
| H5 | Existing analyst acceptance retained | No model/provider/default changes. |
| H6 | Host option added | Uses ordinary graph commands and checked scope, with no new presentation use case. |
| H7 | Existing delivered milestone retained | Artifact-V2 enhancement incomplete; no new performance claim. |
| H8 | Existing modules retained | No remote product module or credential added. |

## 3. Structure

The application owns the batch contract and closed profiles. Native parser modules declare their capability. Infra owns normalization, allocation, staging, segment consolidation and scans in real private modules. It has no production dependency on another adapter or the security implementation. Existing tests still exercise the dependency direction.

## 4. Types and ports

Implemented draft: additive `LargeCaseStore::prepare_local_batch`, checked `LocalBatchRequest`/`PartitionLimits`, optional `StreamingEventParser::partition_profile`, and `GraphQueryFilter::parse_with_host`/`host`. Existing methods retain their signatures. The [source-bound optional companion proposal](https://github.com/ns2switch/irmind/blob/feat/parquet-v2-partitions/docs/development/parquet-v2-partition-replay.md) is not implemented.

## 5. Design deviations

No approved signed layout or golden is changed. The date-only precise builder retains its historical host mapping and replay. The partitioned builder has its own revision. One additional port decision is required: the reconstruction router cannot choose a signed source parser from a record alone. The proposal passes the source without shared mutable routing state or a storage-side format selector.

## 6. Security

The normalization ID is derived from `unicode_normalization::UNICODE_VERSION`; a test pins Unicode 18.0.0 and the approved identifier. Normalization is bounded before and after expansion. Bad source values use typed overflow, retaining actual values. Host tool arguments reject traversal, controls and overflow impersonation; invalid filters never become absent filters. Policy tests deny selectors outside either ceiling. Exact host tests include normalization collisions, overflow and V1 records. Every selected Parquet is hash-verified before scanning.

## 7. Storage and signatures

At most four normalized streams are staged beneath the private case spool. Preflight reserves 16 times each source size plus 64 MiB per source, with a further 64 MiB safety margin; writes are bounded by the reservation. This is deliberately conservative and fails before staging when space is insufficient. RAII handles errors/cancellation; case-open recovery removes orphaned normalized spools. A bounded 16-partition writer pool consolidates revisited segments before publication. The profiler counts normalized streams, segment files and consolidation output at their overlap. **The actual 15 GB temporary-disk peak has not been measured; it belongs to the release benchmark in (e).**

## 8. Quality

Local Linux checks: `cargo fmt --all -- --check` passed; workspace/all-features/all-targets Clippy with `-D warnings` passed. The workspace run excluding the unchanged demo PTY binary passed **501 tests**, with 8 pre-existing manual/benchmark skips. The earlier full run passed the demo PTYs before exposing a new segment-consolidation bug; that bug is fixed. A final infra run passed **94 tests**, with 4 existing manual/benchmark skips. The signed/reconstructed format suite passed **8 goldens** after the final storage changes. Cargo-deny passed advisories, bans, licenses and sources with existing duplicate-version warnings. Documentation checks passed with the pre-existing stale `SECURITY.es.md` warning. Draft CI is pending; no macOS/Windows result is claimed yet.

## 9. External dependencies

The only direct production edge added is `unicode-normalization =0.1.26` for deterministic NFKC. The package is already locked through security; its license is `(MIT OR Apache-2.0) AND Unicode-3.0`. Package counts are unchanged: workspace **565 → 565**, fuzz workspace **308 → 308**. No new package, unsafe block, network client or credential is added.

## 10. Debt and remaining work

Complete source-bound mixed-parser replay after approval. Extend cardinality/replay, cancellation and cross-platform evidence before declaring (c) done. No new fuzzing or 15 GB benchmark is claimed in this checkpoint. Legacy host joins use bounded batches and the same query deadline; their cost must be included in later mixed-case measurements. The final host default remains undecided by measurement, initially 64 and never above 1,024.

## 11. Blocking decision

Approve the additive `partition_profile_for_source(source, record)` companion, defaulting to the already approved `partition_profile(record)`. Only the signed parser router needs an override. The [proposal](https://github.com/ns2switch/irmind/blob/feat/parquet-v2-partitions/docs/development/parquet-v2-partition-replay.md) explains the conflict and regression required. It preserves existing native parser implementations and all signed formats.

## 12. Next step

After approval, finish mixed-source replay and its negative tests, run the complete required CI and merge (c) through the normal gates. Then implement explicit open-case migration/export V5 in its own PR, followed by release-only cloud and host-cardinality benchmarks. Enable default TUI V2 writing only after (c) and (d) are integrated.
