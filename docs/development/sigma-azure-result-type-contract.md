# Sigma decimal ResultType for Azure sign-in

> Historical V4 evaluator and receipt identity. V5 retains the approved projection under the [case 7 and V11 contract](case-7-export-v11-contract.md).

**Status:** proposed for review before implementation.

## Pinned admission and compile audit

SigmaHQ r2026-07-01, SHA-256
`5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085`.
The scanner admitted 3,301 of 3,302 rules in each run. Starting with
the cloud and macOS field table from PR #434, run the V3 rule compiler on
three independent candidate tables, one per projection. The process budget
per file is 512 MiB and two seconds of CPU and wall time. No evidence enters
the audit. Counts are rules with at least one eligible class.

| Candidate | Family | Base / total | Candidate / total | Additional rules | Additional rule/class pairs |
| --- | --- | ---: | ---: | ---: | ---: |
| Decimal `ResultType` | Azure | 63/123 | 70/123 | 7 | 14 |
| `authorizationInfo` | GCP | 13/25 | 14/25 | 1 | 1 |
| `targetResources` and `modifiedProperties` | Azure | 63/123 | 66/123 | 3 | 5 |

A replaces the type of the two current sign-in bindings in a measurement
table. Each of the seven newly eligible rules compiles for both candidate
classes. The proposed rollout below restricts this to the documented
interactive Log Analytics class, which still covers all seven rules in the
compiler trial, with eight additional eligible pairs (seven from newly eligible rules
and one from splitting an already covered class). Existing rules do not
lose eligibility in the trial.

B supplies the exact `permission` and `granted` leaf names. The one rule
uses quoted `'true'` for a provider boolean. Its recovery is conditional on
a reviewed, explicit exact boolean-literal binding and same-item evaluation.
C supplies `targetResources.type` and the documented scalar leaves of
`modifiedProperties` with their Sigma aliases. It does not supply
whole-object names or interpret JSON embedded in values. Its numbers are
compile estimates subject to same-item evaluation. Neither list experiment
authorizes an array projection. The count for A is highest and its
conversion has no array semantics.

## Scope and declaration

Microsoft documents `SigninLogs.ResultType` as a string containing the
sign-in error code, with zero for success. It documents a different meaning
for `AADNonInteractiveUserSignInLogs.ResultType`. Split the existing
`entra-signin-table` class using its authenticated retained `Type`
discriminator: apply the projection only to `Type == "SigninLogs"`; keep
the other explicit values on their existing text binding. Preserve their
parser, mapping and dataset identifiers. Keep the diagnostic resource
class on its existing text binding. The exact text `ResultType` binding
for an existing signed V3 run keeps its historical meaning.
[SigninLogs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) ·
[Noninteractive schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)

The single closed field codec is `projection = "azure_signin_result_type_decimal_v1"`.
Its fixed name is `ResultType`, fixed original path is `["ResultType"]`,
output type is `integer`, and null policy is `absent`. Reject the table
if any element of that combination differs, if the codec appears on
another class, or if a signed V3 table attempts to use it. Rules use
integer literals with existing integer modifiers. A quoted numeric
literal remains text and is incompatible with the projected binding.
There is no new general path syntax or implicit conversion.

## Projection and limits

Use the authenticated retained original and the existing original-row
size, parse and work limits. Inspect one exact top-level key per applicable
row and cache its classification once for rules using it. Charge a field
visit to the existing work budget. Read at most six UTF-8 bytes from the
string after checking its byte length. Accept exactly `0` or an ASCII
decimal with a nonzero first digit, at most six digits, parsed with
checked arithmetic. The inclusive range is 0–999999. No allocation or
normalization is needed. Explicit JSON null or absent yields the existing
null-policy behavior. A present but unprojectable value yields
indeterminate coverage for rules that use this binding, including under
negation. Rules evaluating other fields and evidence ingestion proceed.

| Vector tag | Meaning |
| ---: | --- |
| 0 | Valid integer, followed by eight unsigned big-endian bytes in the vector |
| 1 | Absent or JSON null |
| 2 | Wrong JSON type |
| 3 | Invalid decimal syntax, including empty |
| 4 | String exceeds six bytes |

The tags describe projection outcomes in test vectors. Per-row reason
tags are not new wire fields. Limit is checked before syntax for strings.
Malformed input never becomes a hit or a definitive negative. Count a
row at most once per source and once per affected rule, using the
existing V3 indeterminate lists, time/work limits and cancellation.

## Receipts, verification and export

Use evaluator `irmind-sigma-evaluator-v4` for tables containing this codec.
The canonical field-table V1 object retains the exact TOML bytes, which
commit to the split, input, output and codec. Reuse the signed
`SigmaRunV1` layout, V3 result object, statuses 5 and 6, and V10 proof
framing. Status 5 means an otherwise complete scan has indeterminate rows.
Status 6 retains existing precedence for incomplete class coverage.
An operational stop retains its existing precedence over both. Retain
both class coverage and indeterminate counts even when one determines the
status. Signed reports and verification read the authenticated counts.

The verifier dispatches by signed evaluator identity, rechecks table
admission, source and row references and reconstructs the exact
projection from authenticated Parquet originals. No fallback to V3 or to
a textual value is permitted. A different table, altered result, changed
version marker or removed row-gap count must fail against the original
receipt. If package case admission lands first, use the versioned
case-admission gate with the same checks on the evaluator, checkpoint
and table digest; a package run must not accept an ungated identity.

## Review vectors

[Generator](sigma-azure-result-type-vectors/generate.py) ·
[Canonical bytes](sigma-azure-result-type-vectors/wire.json).
Vectors fix positive and negative projections, a signed-receipt body with
an exact hit, an indeterminate receipt body, and altered receipts with
their original proof materials. The signed receipt challenge itself is
the existing case-entry challenge. Implementation must replay the
vectors and also verify an actual signed case and V10 export. Include
integration tests for a negated rule over malformed data, an unaffected
rule sharing the same row, and a noninteractive row with identical bytes
that keeps the text binding.
