# Typed V10 proof objects for Sigma and reports

This document specifies the object bodies referenced by the approved
[V10 receipts and header vectors](https://github.com/ns2switch/irmind/pull/389).
It uses the approved kinds, framing, domain-separated commitments and counts.
The body schemas below are pending approval.

## Primitives

Use the V10 scalar grammar. A list is a big-endian u64 count followed by the
specified elements. An optional value is u8 0 or u8 1 followed by the specified
value. A discriminant outside a closed table is invalid. Strings use the
field's existing domain limits wherever applicable. Text introduced here is
UTF-8 with the per-field limits below. Identifiers use exact bytes with
lexical ordering. Lists defined as sets must be strictly ordered and unique.
Reject trailing bytes. Check object size, element counts and checked sums
against applicable limits before allocation. The complete section is bounded
at 128 MiB and each pack, result or report bundle has its approved ceiling.

Use these common references.

| Name | Exact encoding |
| --- | --- |
| Audit checkpoint or receipt | Sequence u64 and raw entry hash. Resolve within the signed case. |
| Source instance | Source manifest entry sequence u64, entry hash and evidence SHA-256. Identical source bytes can belong to separate signed instances. |
| Artifact | Artifact entry sequence u64, entry hash and physical artifact SHA-256. |
| Row | Source instance, original logical record number u64, artifact, physical zero-based row index u64. Both references must resolve to the same authenticated record. Compaction lookup uses the active inventory at the receipt checkpoint. |
| Canonical object | ASCII tag and NUL followed by its exact fields. Raw rules and rendered documents keep their original byte encoding. The fixed kind and raw SHA-256 bind those raw bytes. |

## Sigma objects

| Kind | Tag | Body in order |
| --- | --- | --- |
| 0 | `irmind-sigma-pack-manifest-v1` | List of rule entries sorted by relative path. Each contains path text, canonical rule ID text, optional version text, optional author text, raw rule SHA-256 and rule byte count u64. Paths are bounded slash-separated relative names within the admitted pack. IDs and paths are unique. A missing upstream ID uses `sha256:<lowercase rule digest>`; a missing version stays absent. The signed admission separately binds origin and license. |
| 1 | Exact YAML | The untouched admitted UTF-8 document. Match the path-independent digest and byte count in the pack manifest. Global admission is additional to per-rule syntax and coverage checks. |
| 2 | `irmind-sigma-field-table-v1` | Table ID text, version text and exact bounded UTF-8 table text. The table uses the closed TOML schema below. Digest the entire body including original TOML bytes. |
| 3 | `irmind-sigma-source-scope-v1` | List of selected source instances sorted by manifest sequence. Each must be in scope at the checkpoint. The enclosing run supplies the mandatory half-open time range. |
| 4 | `irmind-sigma-compiled-rules-v1` | List of rule ID text, raw rule SHA-256 and strictly ordered u64 field-table variant indices, sorted by rule ID and hash. Include all requested rules, including ineligible rules with an empty variant list. The evaluator ID pins the compiler and operators. Complete reproduction recompiles those exact bytes against the exact authenticated table and scope. |
| 5 | `irmind-sigma-run-results-v1` | Coverage entries followed by match entries. Coverage entries are ordered by rule ID and hash and use the same ID and digest pair as kind 4. Each has a u8 classification and optional bounded detail text. A match is rule ID text, rule hash, Row and optional query-limit receipt. Matches sort by rule ID, rule hash and existing stable event order, with Row as a unique tie-breaker. |

The field table consists of a versioned `[[variants]]` array. Its index is
the zero-based ordinal in the authenticated table. Each variant fixes
`product`, `service`, `category`, `parser_id`, `parser_version`,
`mapping_id`, `mapping_version` and `dataset` or `channel`.
Omitted logsource selectors match only the explicit union. A variant's
closed event discriminators are equality or finite membership on a typed
common or original field. Each field binding has a Sigma name, one typed
column or a bounded array of exact source-field path segments, and its
closed type and null policy. Reject overlapping declarations, duplicate
bindings, unknown keys and undeclared source versions. Unknown or unavailable
fields fail rule compilation for those sources. No free-form expressions
or engine evaluation code are admitted from the table.

Coverage codes are u8 0 eligible, 1 unsupported logsource, 2 unsupported
field or incompatible field type, 3 unavailable selected evidence, and 4
unsupported rule syntax or modifier. A noneligible entry requires a detail
of at most 512 bytes and has no matches. There is exactly one coverage entry
per requested rule. Eligible entries carry no detail. A status from the
enclosing `SigmaRunV1` describes the entire run, including an incomplete
scan when there are zero matches. The receipt count equals the number of
match entries. The verifier reconciles source, artifact, rule and inherited
capture limits against the case checkpoint. Export authentication checks
these references without running rules; full reproduction reruns eligible
rules with the evaluator identified by the receipt.

Rule IDs, versions, authors, and normalized paths are limited to 128, 128,
512 and 512 bytes respectively. Field-table body is limited to 512 KiB, with
at most 1,024 variants and 128 fields per variant. Proof-set descriptors are
strictly ordered by kind and hash. A shared immutable object can serve several
receipts. The verifier rejects any object outside the union referenced by the
verified receipts. Bounds apply to rows, lists and aggregates even when the
same object is shared.

## Report objects

| Kind | Tag | Body in order |
| --- | --- | --- |
| 0 | `irmind-report-citations-v1` | Ordered list of finding ID text, confirmation audit reference and citation list. A citation is u8 0 plus Row or u8 1 plus Source instance and Artifact. An artifact-level assertion is confined to authenticated artifact facts. A record-level assertion needs a Row. |
| 1 | `irmind-report-analyst-sections-v1` | Four bounded text slots in order scope, methodology, context, recommendations. Each slot is present even when empty. An absent kind 1 means no analyst material was published. |
| 2 | `irmind-report-coverage-v1` | Ordered lists of unavailable sources, loaded skill coverage gaps, committed query limits and partial Sigma runs, in that order. The four counts are mandatory. The first list is source instance and u8 reason (0 unavailable, 1 availability unknown). Skill gaps are the signed skill load reference and a bounded zero-based gap index from its pinned content. Query and Sigma items are signed receipt references. |
| 3 | Exact report bytes | The exact Markdown or PDF bytes covered by the publication receipt. Verify size, media kind, digest and proof-set membership. |

Resolve every finding ID against its analyst confirmation before or at the
checkpoint and its existing, verifiable event facts. No finding can have an
empty citation list. Sort findings by the existing stable event order and
finding ID, and keep unique citations in that ordered finding plan. The
coverage collections sort by signed sequence, then the reason or slot.
Compute coverage from signed case evidence and declared tool/skill status.
Availability not established by the signed snapshot is represented as
unknown. A partial receipt cannot support a claim of absence.

A present optional model-draft hash in `ReportPublishedV1` resolves the
existing signed `ModelReply` entry at or before the checkpoint. It covers
only a typed plan of approved templates and finding/citation references.
Verify the plan's selected references against kind 0 and derive facts from
the authenticated inputs. Unrestricted draft text can be edited by the
analyst in the four kind 1 slots. It gains publication authority only through
the analyst's signature over those exact bytes. This needs no new proof kind
or second draft receipt.

Cap each analyst section at 16 KiB and counts at the existing policy and
receipt limits. The renderer version fixes templates, section order and
layout. Identical inputs and language reproduce the exact rendered bytes.
Without the renderer, verify the authenticated publication and references
and report which reproduction check was unavailable.

## Verification vectors

The [generator](../../crates/testkit/fixtures/contracts/sigma_report_objects.py)
and [vectors](../../crates/testkit/fixtures/contracts/sigma_report_objects.json)
use synthetic objects. Reject a duplicate kind/hash descriptor, a missing or
extra proof object, bytes after a typed body, a reordered proof set, wrong row
identity, an unconfirmed or uncited finding, and missing partial coverage.
The objects are wire fixtures. Resolver tests must independently authenticate
the referenced case rows, checkpoints, policy and signatures.
