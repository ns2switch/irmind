# Case 7 and export V11 · Phase 0 contract

Status: approved, including the Sigma text-width correction in `6375a5ca`. The existing Rust Sigma codecs use u32 lengths. The first generator used u64 for Sigma text as well as for audit text. The corrected vectors preserve the existing Sigma objects and use u32 in the new receipt. Baseline: [v0.7.4](https://github.com/ns2switch/irmind/releases/tag/v0.7.4), commit `04f4b5dc0de45070a533d61ec32e12af546ff980`. This phase consolidates the format before v0.8 work begins. [Versión en español](../es/development/case-7-export-v11-contract.md).

## Format inventory

“Remove” means removing production readers, writers, resolution paths and compatibility tests. The release tag and archived contracts preserve the historical specification. Keep only the old bytes needed to exercise rejection in the active suite.

| Current or historical item | Case 7 decision |
| --- | --- |
| Case markers 6 and earlier, archive V10 and earlier | **Remove** their verification and interpretation paths. Recognize their markers in the admission check only. |
| Sigma evaluators `v1`, `v2`, `v3`, `v4`, and the two shipped `v3-case-admission-v1` and `v4-case-admission-v1` names | **Consolidate** into `irmind-sigma-evaluator-v5`. Delete evaluator dispatch by legacy version, suffixes and the legacy row-only match validation. The current V3/V4 choice is based on the table's decimal binding. V5 uses the actual approved binding and always compiles by source class. |
| `SigmaRunV1`, which carries admission policy in the evaluator name | **Replace** with the receipt below. Reject a V1 receipt inside case 7, including one carrying the V5 identifier. |
| `SigmaRunResultsV1` and `SigmaRunResultsV2` | **Remove** their stand-alone bodies and decoder dispatch. Inline or factor the list codecs that are shared with the live V3 body. |
| `irmind-sigma-run-results-v3` and status codes 0–6 | **Keep** the exact wire. The class matrix becomes mandatory, including an empty matrix where applicable. An evaluation preserves its partial result and reason. |
| Sigma rule, manifest, exact field table, source scope and compiled rule-set objects | **Keep** kinds 0–4. Kind 5 accepts only the V3 result body. Keep installed-package proof kinds 6–8 with their current roles, hashes and reachability checks. |
| `SigmaCaseRunAdmissionV1`, `SigmaPackAdmissionV1`, `SigmaPackageInstallationV1` and the signed Sigma catalog index | **Keep** their wire and signature domains. Apply the case-7 binding below to the per-run admission. Preserve both local and catalog package installation, the catalog key and persistent version floor. |
| `ReportCoverageV1` | **Remove** the historical vector and generation path from active coverage tests. V0.7 already writes V2. Keep an explicit rejection vector for a V1 body under a current report receipt. Extract shared vector-generation helpers from the old body generator. |
| `ReportCoverageV2`, `ReportPublishedV1`, cited rows, analyst sections and Markdown/PDF | **Keep** exact bytes, authenticated resolution and distinct subagent coverage coordinates. Fold the historical report branches for Sigma into the single current run path. Keep separate explanations for operational limits, unavailable exact fields and coverage gaps. |
| Native mapping manifest V1 | **Remove** compatibility with a V1 identity as a released native mapping recipe. **Keep** named provisional development/bootstrap provenance and its warning. The current dev build can produce it, including the Azure capture binding. Keep the separate declarative extraction descriptor's nested V1 and domain, which are current production inputs. |
| Native mapping manifest V2 | **Keep** the identity recipe and release verification on all five targets. Explain any input-driven hash change as described below. |
| Old Parquet and graph audit kinds, old layout migration receipts and old skill snapshots | **Remove** obsolete payload dispatch and redundant scattered checks. A historical-only audit token may survive in the central rejection path. The `SourceManifestV1` data embedded in the current `SourceManifestV2` remains part of the current wire. |
| Legacy mapping-table interpreter marker | **Remove** any stale claim that the retired V1 interpreter can run. Keep V2, global operation authentication and the existing explicit unavailable-interpreter outcome for an unusable installed definition. |
| V10 proof framing, report object kinds 0–3 and export port | **Keep** their bytes and membership requirements. The export method remains `export_case`. Rename implementation-only V10 labels where they now name the V11 container. |
| Audit V2, chain and signatures, seal and inventory, ParquetArtifactV3, ParquetLayoutV1, source records, captured queries, skills and catalog proofs, subagent branches, budgets, and folder-ingest outcomes | **Keep** the active formats and controls. A `V1` or `V2` suffix in an active schema has its own meaning. No marker or wire changes for these items. |

The inventory follows the [V10 wire](sigma-report-v10-wire.md), [proof objects](sigma-report-proof-objects.md), [source-class compiler](sigma-source-class-compilation-contract.md), [Azure decimal projection](sigma-azure-result-type-contract.md), [package contract](sigma-package-installation-contract.md) and [native manifest V2](native-mapping-manifest-v2-contract.md). Final cleanup PRs identify remaining compatibility-only fixtures, feature aliases and jobs by file. Active formats with historical names are kept wherever still used in a signed object.

## One Sigma evaluator and a separate admission mode

V5 always compiles a source-class plan using the authenticated field table and selected-source set of the run. Preserve the approved Windows, cloud, network and endpoint projections. The decimal `ResultType` binding is valid only for `Type == "SigninLogs"`. A table whose bindings are all textual is valid with V5. Keep the existing outcome for unavailable exact fields, including the Kubernetes/GKE 33-IP case and invalid `status.code`. An indeterminate row has no match verdict even under negation. Keep limits, budget accounting, deterministic ordering and the precedence of operational stop, class gaps, row indeterminacy and complete. Verification resolves the signed scope, source-class plan and exact cited rows, including the predicate and authenticated artifact. A build missing the required evaluator or mapping reports it explicitly and cannot certify full verification using a reduced row check.

Add audit kind `sigma-run-v2`. Its payload is the lowercase hexadecimal encoding of the following concatenation, without separators or trailing bytes.

| Order | Field and encoding |
| --- | --- |
| 1 | ASCII `irmind-sigma-run-v2` and one NUL |
| 2 | Case ID text, checkpoint sequence u64, raw checkpoint hash (32 bytes) |
| 3 | Pack admission, artifact inventory and selected source digests (32 bytes each) |
| 4 | Time start and end i64, UTC microseconds |
| 5 | Compiled rules and field table digests (32 bytes each) |
| 6 | Evaluator text, exactly `irmind-sigma-evaluator-v5` |
| 7 | **Admission mode** u8, closed values `0` or `1` |
| 8 | Reserved units u64, used units u64, existing status u8 (0–6), matched rows u64 |
| 9 | V3 result body and proof-set digests (32 bytes each) |

All integers are big-endian. Sigma text is a u32 byte count then UTF-8, with the existing 36-byte case ID and 128-byte evaluator bounds. The surrounding audit challenge still uses u64 length prefixes. Keep existing time, reservation, result size and match validation. The receipt and any finding entries use the existing audit challenge and have the same atomic publication boundary.

- **0 · Direct local import.** The run references an authenticated global `SigmaPackAdmissionV1` with origin `LocalDirectory`. It has no paired case-run admission and references no installation, catalog or metadata proofs. The existence of an installation of a pack with the same manifest does not confer authorization. A pinned release archive can use the installed-package path.
- **1 · Installed package.** Require exactly one authenticated `SigmaCaseRunAdmissionV1` immediately before this run. The run checkpoint and its outer chain predecessor both identify that admission; the admission checkpoint identifies its own immediate predecessor. Bind both to the same case and to the authorized Analyst signatures, with `origin=analyst` and no evidence reference. The admission uses V5 and the current wire, including the existing optional digest encoding with tag `1` and the exact installation digest. Match the pack admission and manifest, inventory, source scope, time range, field table, compiled-rule set, evaluator and reserved work. Verify the signed installation and its proof objects for its exact origin. Check eligibility while preparing the append under the case lock and preserve the existing policy and catalog version floor. Full verification authenticates that historical execution rather than querying the live catalog.
- Reject an unknown mode, a missing, unused, mismatched or reused admission, objects that only a different mode can reach, a mode-0 pinned archive, invalid signatures, and invalid record ordering. The checkpoint commits to the admission hash in mode 1. No second digest slot is required.

## Case marker and archive

The first case audit record remains `CaseCreated` at sequence 1 with the usual Analyst origin, zero previous hash and no evidence. Change only its JSON `version` from 6 to 7. Keep its current key order `version,title,severity,scope,budget,source_queries` and the existing budget and query allocation schemas. The resulting record and every downstream chain entry must be signed for that case. There is no in-place marker rewrite.

Export V11 starts with ASCII `IRMIND-EXPORT-V11` and NUL, then the u64 length of the compact UTF-8 JSON header. Its key order is `version,case_id,title,severity,scope,seal`, with `version:11`. Keep the existing seal fields and challenge byte for byte. V11's case chain must begin with a valid case-7 record and agree with the header metadata and final case seal.

| Position | Section with leading u64 count |
| --- | --- |
| 1–4 | Audit entries, evidence, original sources, operations (case and referenced global) |
| 5–8 | Mapping proofs, Parquet, skill proofs, skill catalog proofs |
| 9–12 | Subagent branches, source query captures, Sigma proofs, report proofs |

All 12 counts remain present even when zero. Require EOF after the report section. The existing per-section order, limits and duplicate/dangling/orphan checks stay in force. The Sigma and report proof descriptors remain kind u8, digest 32 bytes, body length u64 and the exact body. Retain the family-specific proof-set commitment encoding and object digest checks. The existing 1 MiB framed-record limit, 64 MiB proof content limit, 128 MiB per case and proof family, 5 million audit-entry limit, 1 million evidence and source count ceilings and 2,000,000,000,000-byte archive limit continue to apply, alongside the stricter object-specific and policy bounds. No new section, counter or format changes outside the consolidation.

## Central rejection and upgrade

Use a single application format classifier for the case marker and archive version. Preserve transport-level validation of each input and return the same typed reason to CLI, TUI and export verifier. On opening or verifying a case, admit its bounded first entry before reading later payloads. Check the first kind, sequence, case ID, signer, signature and hash before any custody decision or mutation. On archive admission, recognize the canonical bounded magic (at most 26 bytes including NUL, with a nonzero u32 in canonical decimal) before allocating the header or reading the body. Check a current header's version and the authenticated case marker as well. An old magic is only a format hint. It provides no statement about authenticity or the producing patch.

| Marker | User guidance |
| --- | --- |
| Case 6 / export V10 | Use the original IRMind v0.7.x binary that created it. A v0.7.4 case with folder-ingest outcomes can require v0.7.4. |
| Case 5 / export V9 | Use the original v0.6.x binary. |
| Case 4 / export V8 | Use the original v0.5.x binary. |
| Export V7 / V6 | Use the original v0.4.x / v0.3.x binary respectively. |
| Case 3 and earlier, recognizable unversioned cases, export V5 and earlier | Use the producing binary. Those markers do not reliably identify a single release series. |
| Future marker | This build cannot read the format. Use the newer binary that produced it. |

For example, `This is case format 6. Use the IRMind v0.7.x binary that created the case, or re-ingest the verified originals into a new case.` When the format provides no reliable version, use the same guidance without a release series. Show the release series only when the marker supports it. Do not derive an exact patch from a title, a path or an unsigned header. Report malformed or duplicate current markers, truncated framing and a header/magic mismatch as invalid format. A signed older case marker inside V11 fails version admission. Historical-only record kinds inside case 7 fail verification, even with a valid audit signature. Opening, verification, export, seal recovery and any startup cleanup or deletion involving an old case refuse its contents and leave it intact. Case listings can still show independently available metadata without certifying the case. The existing organization authorization and key checks apply equally to current cases.

Keep the binary, compatible data directory and keys used for v0.7.x to open, verify and export those cases. Homebrew does not retain earlier versions. Before upgrading with open v0.7.x cases, download and verify the exact producing binary and its helper from the GitHub release. The bilingual guide and rejection message link to tag-specific instructions for SHA-256, Sigstore and GitHub attestation verification. To delete an old case, use its v0.7.x binary, which refuses deletion of a sealed case, or remove the case directory manually outside IRMind. Manual deletion is irreversible and destroys the case and its local proof files. The guide distinguishes this from a signed deletion. For a new case, re-ingest the verified originals and rerun the investigation steps that are needed. Exports are verified with the producing version. The pre-1.0 policy supplies no migration or marker conversion.

The V2 native manifest recipe is unchanged. A source or dependency edit inside one mapping's measured production closure can still change its identity. Compare the release manifest for all 19 native identities with the baseline, attribute changes to the reachable inputs and confirm equality across the five release targets. Keep the distinct provisional marker in development and surface it in verification. Keep installed Sigma packages, exact index and archive hashes, license and rollback history when the same authenticated global store and keystore are available. Package records remain global and independently versioned. Apply the existing minimum IRMind-version check and compile installed rules against the case-7 field table at run time. Review coverage with `/sigma info` and give each new case its own signed run admission for an installed package. An old case receipt does not admit a run in a new case.

## Independent vectors and acceptance tests

The [generator](case-7-export-v11-vectors/generate.py) requires Python 3 and OpenSSL 3 with Ed25519 support. Run it with no arguments and compare its output with [wire.json](case-7-export-v11-vectors/wire.json). It uses deterministic public test seeds and independently checks each signature with OpenSSL. The sealed empty archives are full framing fixtures. The Sigma receipt fixtures bind synthetic hashes and signed case checkpoints; they test codec and linkage, with no claim that those hashes identify a complete evidence archive. The prior [class-plan vectors](sigma-source-class-compilation-contract.md), [Azure projection vectors](sigma-azure-result-type-contract.md) and [ReportCoverageV2 vectors](report-subagent-coverage-v2.md) also remain normative for the unchanged bodies and projection semantics.

Production tests must reproduce the bytes and authenticate the actual inventory, source class, artifact and row, operations, installation, proof reachability, case prefix and signatures. Exercise both modes with the same V5 identifier, both catalog and local installed-package origins, unavailable Azure and Kubernetes exact fields, and rejection after changing just the signed mode or prior admission. Exercise ordinary and partial Sigma runs with confirmed findings feeding the bilingual reports through V11. Use `preserve_order` and 1/N workers for determinism. Keep current security tests, fuzz targets and controls; retarget the archive harness to valid V11 and historical magic rejection. Keep V3 result-body fuzzing active.

## Delivery and measurements after approval

Land format admission, V5 receipts and V11 with matching writer, verifier and release tests. A later cleanup PR removes obsolete code and fixtures. Follow with dependency, duplication and workflow review, then bilingual format guides, an archive index and the changelog. An intermediate merge must not emit mixed formats. Keep the full matrix green per PR, preserve the signing and release checks and update only jobs and fixtures tied to a retired format. Hooks, MCP and the engine API are outside Phase 0.

Measure baseline v0.7.4 and final candidate using the same production source-count method, runner labels, cold-cache conditions and toolchain where available. Report production Rust lines excluding tests, generated and vendored code, workspace crate counts with helper and fuzz counts identified, executable sizes by target and separate EVTX sizes, cold compile durations and full matrix duration with queue time separate. Check cargo-deny and enumerate removed features, dependencies and workflows. Limit deduplication to clear shared code with current semantics. Record tool versions and any runner drift alongside the paired data.

Run the full distribution rehearsal on the exact tagged tree before publishing `v0.8.0-alpha.1`. Use only synthetic keys and data in the normal E2E tests. Preserve cross-platform CloudTrail and Sysmon, mixed-folder ingestion, Azure capture reopen, signed Sigma, Markdown/PDF, seal and export verification. Test direct and installed Sigma modes, case-7/V11 rejection of older formats, and the existing native reproducibility, checksum, Sigstore, attestation, SBOM, build-environment and installer checks. Prepare the prerelease notes in English and Spanish around consolidation and the format break.
