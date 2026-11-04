# Artifact V2 partitions: implementation review checkpoint

This report is for the analyst reviewing step (c). This is an unfinished draft, not a completion or merge request.

## 1. Summary

The approved contract document is merged in [PR #169](https://github.com/ns2switch/irmind/pull/169). [Main CI passed](https://github.com/ns2switch/irmind/actions/runs/41787683760). Step (c) has a separately tested implementation draft. The approved source-aware callback and bounded canonical ordering are implemented. A new golden exposed historical JSON fast-path dependence on the serde map feature; a separate compatibility decision is required before further changes. Production CLI/TUI writing remains V1; migration/export V5 and release benchmarks are not implemented here.

## 2. Milestones

| Milestone | State relevant to this change | Completion evidence |
| --- | --- | --- |
| H0 | Existing gates retained | Dependency direction is part of the passing local suite. |
| H1 | Additive checked host selector | Invalid values and both scope ceilings tested; existing wire goldens pass. |
| H2 | Approved batch/profile additions implemented | Local/object ingestion share preparation; signed source-bound replay tested. |
| H3 | Existing guard retained | No new path sends parsed or indexed text directly to the model. |
| H4 | Existing custody retained | Existing source, audit, signature and seal encodings unchanged. |
| H5 | Existing analyst acceptance retained | No model/provider/default changes. |
| H6 | Host option added | Uses ordinary graph commands and checked scope, with no new presentation use case. |
| H7 | Existing delivered milestone retained | Artifact-V2 enhancement incomplete; no new performance claim. |
| H8 | Existing modules retained | No remote product module or credential added. |

## 3. Structure

The application owns the batch contract and closed profiles. Native parser modules declare their capability. Infra owns normalization, allocation, staging, segment consolidation and scans in real private modules. It has no production dependency on another adapter or the security implementation. Existing tests still exercise the dependency direction.

## 4. Types and ports

Implemented draft: additive `LargeCaseStore::prepare_local_batch`, checked `LocalBatchRequest`/`PartitionLimits`, optional `StreamingEventParser::partition_profile`, and `GraphQueryFilter::parse_with_host`/`host`. Existing methods retain their signatures. The analyst-approved optional `partition_profile_for_source(source, record)` is implemented with a compatible default. The signed parser router rejects unknown sources; native modules keep their own profiles. No other port change is implemented.

## 5. Design deviations

No approved signed layout or golden is changed. The date-only precise builder retains its historical host mapping and replay. The partitioned builder has its own revision. The previously requested source-aware companion is approved and implemented, without shared mutable routing or a storage-side format selector. The new reproducibility test identified a pre-existing JSON normalization difference, also affecting historical V1. The [compatibility proposal](https://github.com/ns2switch/irmind/blob/feat/parquet-v2-partitions/docs/development/json-line-order-compatibility.md) is not implemented; normalized historical output has not been altered.

## 6. Security

The normalization ID is derived from `unicode_normalization::UNICODE_VERSION`; a test pins Unicode 18.0.0 and the approved identifier. Normalization is bounded before and after expansion. Bad source values use typed overflow, retaining actual values. Host tool arguments reject traversal, controls and overflow impersonation; invalid filters never become absent filters. Policy tests deny selectors outside either ceiling. Exact host tests include normalization collisions, overflow and V1 records. Every selected Parquet is hash-verified before scanning. Graph summaries label counts of overflow event files by their signed reason; these are file counts, not a claim about the percentage of events.

## 7. Storage and signatures

At most four normalized streams are staged beneath the private case spool. Preflight reserves 16 times each source size plus 64 MiB per source, with a further 64 MiB safety margin; writes are bounded by the reservation. This is deliberately conservative and fails before staging when space is insufficient. A streaming hash also binds the normalized spool to the emitted parser records; truncation is detected before publication. RAII handles errors/cancellation; case-open recovery removes orphaned normalized spools and owned reconstruction workspaces. Reconstruction workspaces are now case-local. Recovery rejects a symlink in place of an owned workspace. A bounded 16-partition writer pool also flushes buffered column data at the batch-byte budget and consolidates revisited segments before publication. Out-of-order completed groups use a bounded, hash-checked external merge sort, with two readers and at most 64 run levels. Ordered input avoids that pass. Sorting stays inside the private case spool and preflights an additional twice the largest staged source plus 64 MiB. Historical builders retain their exact flush rules. The profiler counts normalized streams, segment files and consolidation output at their overlap. **The actual 15 GB temporary-disk peak has not been measured; it belongs to the release benchmark in (e).**

## 8. Quality

Local Linux results are explicit, not a declaration of completion:

| Check | Result |
| --- | --- |
| rustfmt | Passed after the implementation changes. |
| Clippy, workspace/all-features/all-targets, `-D warnings` | Passed. |
| Workspace suite excluding the unchanged demo PTY binary | **511 passed, 1 failed, 8 existing skips** in 152.390 s. The sole failure is the newly added physical-byte golden under the workspace's `preserve_order` feature graph. |
| Earlier full run including PTYs | All 12 demo PTYs passed. A new native-cloud partition assertion failed, then was corrected and passed in the subsequent run. This is not a final full-suite pass. |
| Format tests | The new physical-byte golden passed in the package-only default graph. With explicit `preserve_order`: **9 passed, 1 failed, 0 skipped**, 1.450 s. The failure is the new golden; the eight existing goldens remain unchanged and pass. |
| Final infra suite | **101 passed, 4 existing skips** in 53.149 s; includes orphan recovery and symlink rejection. |
| Documentation | Passed, with the pre-existing stale `SECURITY.es.md` warning. |

The last published head before this update, `58f7151`, passed [CI](https://github.com/ns2switch/irmind/actions/runs/41794152019): Linux 7m38s, macOS 6m06s, Windows 9m36s and alternate-format checks 2m40s. Those results do not validate the newer changes or the newly exposed regression. No required test is disabled to obtain a green check. Cargo-deny passed on the earlier draft; it has not been rerun for this checkpoint.

## 9. External dependencies

The only direct production edge added is `unicode-normalization =0.1.26` for deterministic NFKC. The package is already locked through security; its license is `(MIT OR Apache-2.0) AND Unicode-3.0`. Package counts are unchanged: workspace **565 → 565**, fuzz workspace **308 → 308**. No new package, unsafe block, network client or credential is added.

## 10. Debt and remaining work

The callback and interleaved Linux audit regression are implemented. Sources sharing a hash cannot silently switch parser/builder generation through a different filename; tests require explicit migration. Bounded sorting and native mixed-parser reconstruction pass locally. The historical JSON fast-path issue blocks reproducibility and must be resolved before (c) can merge. No new fuzzing or 15 GB benchmark is claimed. Legacy host joins use bounded batches and the same query deadline; their cost remains part of later mixed-case measurements. The final host default remains undecided by measurement, initially 64 and never above 1,024.

## 11. Blocking decision

Approve the [JSON compatibility correction](https://github.com/ns2switch/irmind/blob/feat/parquet-v2-partitions/docs/development/json-line-order-compatibility.md): a canonical new JSON parser version, plus historical replay accepted only when its complete output matches the signed artifacts. The source-aware partition callback needs no further approval. The earlier instruction requires asking before changing historical hash-dependent behavior, so no JSON fast-path normalization fix has been applied.

## 12. Next step

After the compatibility decision, implement and test that correction without changing signed wire encodings or historical goldens, complete required CI and merge (c) through the normal gates. Then implement explicit open-case migration/export V5 in its own PR, followed by release-only cloud and host-cardinality benchmarks. Enable default TUI V2 writing only after (c) and (d) are integrated.
