# Exact Sigma source fields for v0.7

**Status** · Defender, EVTX and Microsoft 365 approved. Revised
Kubernetes and GKE projection and Sigma coverage vectors submitted for review.
Production implementation of the revised contract awaits approval.

## Kubernetes and GKE

Clustered audit mappings retain the canonical common projection in the
Parquet `text` column. A client can influence Kubernetes `sourceIPs` through
`X-Forwarded-For`. Invalid, repeated or oversized values in an otherwise
admitted record cannot prevent the audit event from being indexed. The signed
original stays intact and available through the existing evidence workflow.

Use one compact UTF-8 JSON object with keys `common`, `format`, `original`
and `unavailable` in that order. Recursively sort object keys in lexical
order. Write no surrounding whitespace or final newline:

- `common` is the unchanged canonical CommonEvent object. The optional
  scalar IP projection uses the original first address only if valid.
  An invalid first address omits that scalar and its observation while
  retaining the event. Do not promote a later forwarded address.
  A malformed GKE status leaves the normal outcome unknown. Apply the same
  omission to an optional client-controlled common field that fails its
  conversion. Ordinary record framing and custody checks still apply.
- `format` is `irmind-kubernetes-sigma-projection-v1`.
- `original` contains only the approved exact paths and retains valid values
  verbatim. Native Kubernetes uses `original.sourceIPs`, EKS and AKS use
  `original.audit_event.sourceIPs`, and GKE uses
  `original.protoPayload.status.code`. A genuinely absent field has no entry
  in either object. A present empty IP array remains an empty array.
- `unavailable` is a bounded object keyed only by
  `sourceIPs`, `audit_event.sourceIPs` or `protoPayload.status.code`, as
  appropriate for the source class. Derive these keys and reasons in the
  mapper, never copy them from the source. Each value is exactly one of
  `overflow`, `invalid_ip`, `duplicate`, or `unexpected_type`.
  Unavailable paths have no value in `original` and never carry input text
  in `unavailable`. A path cannot appear as both available and unavailable.

For IP arrays, check the array type and the maximum of 32 elements first.
Then inspect elements in source order and use the first failure. Check
string type, the 45-byte cap, IP parsing and duplicate address in that
order. Byte or count overflow uses `overflow`. An ill-formed IP uses
`invalid_ip`. Equivalent parsed IPv6 addresses count as duplicates.
Preserve source ordering and spelling when the entire array is valid.
For GKE status, use `unexpected_type` for a present non-integer, including
null, and for a non-object ancestor on the exact path. Use `overflow` for
an integer outside the 0 through 16 range used by the GKE outcome mapping.
The retained gRPC code stays distinct from native Kubernetes HTTP status.

The canonical common object retains its existing 65,536-byte bound. The
new envelope alone may add up to 2,048 bytes of bounded metadata, for a
maximum encoded length of 67,584 bytes. The allowance is needed to record
an unavailable field even when the unchanged common object already fills
its limit. The decoration bound covers the maximum 32 valid ASCII IP
strings of 45 bytes each, their keys and punctuation, and the closed reason
values. It does not increase any input, CommonEvent or existing wire
frame limit. The scanner accepts the extra bytes solely for this
authenticated projection and validates both bounds independently.

Use new mapping implementation identities and keep the Parquet schema and
the original, source and row references. Retain the original request and
response bodies in the source evidence only.

## Coverage for an unavailable exact field

An applicable, compiled rule that references an unavailable path is
indeterminate on that row. Perform the availability check before field
predicates, including positive, negated, null and exists predicates, and
before a predicate prefilter could suppress this coverage signal. Do not
substitute a typed common field for the exact original path. Other rules
may evaluate the row, and the affected rule can independently match other
rows. A missing field with no marker keeps its ordinary semantics.

The execution shows a count of distinct examined rows with any unavailable
exact field per selected source. It also shows the count of indeterminate
rows for each affected rule. Count one row once per source even if several
rules or fields are affected. Count it once per rule even if that rule
references several unavailable paths. When an existing budget, cancellation
or time limit stops the scan, mark these counts as covering the examined
portion. Treat an unavailable field as a potential source-quality or
tampering signal to investigate alongside the original.

### Proposed authenticated result extension

Use the existing Sigma proof slot 5 and a new body domain
`irmind-sigma-run-results-v2\0`. After the domain, write the two existing
V1 coverage and match lists byte for byte in their established order.
Append these two lists, each preceded by its big-endian u64 count:

| List | Entry bytes and order |
| --- | --- |
| Unavailable rows by source | Existing 72-byte `V10SourceReference`, then nonzero big-endian u64 row count. Sort by signed source manifest sequence. Each source must be present in the signed selection. |
| Indeterminate rows by rule | Existing rule ID text and 32-byte rule digest, then nonzero big-endian u64 row count. Sort by rule ID and digest. Each entry must identify an eligible requested rule, and its count must fit the total unavailable rows in examined sources. |

Reject duplicate or out-of-order references, zero counts, count overflows,
and any count that exceeds the authenticated record inventory it describes.
Bounds for proof objects and rule lists stay unchanged. Rules with
indeterminate rows still use the existing eligible classification. This
keeps matches from other rows and allows the two new counts to describe
observed gaps separately from a rule skipped at compilation.

Use `irmind-sigma-evaluator-v2` for the new behavior. Reserve status byte
`5` (`exact_fields_unavailable`) in the existing `SigmaRunV1` layout when
the full scan reaches the end with at least one indeterminate rule row.
The existing early-stop status takes precedence when applicable and the
result body still includes the observed counts. A run with no applicable
rule affected can complete and still show the per-source quality counts.
The report's existing `ReportCoverageV2` partial-run reference authenticates
the result proof, and its limitations section prints the affected source
counts. Verification authenticates the source and rule references and
reconciles status and counts. The selected-source set also bounds the number
of source counters. Full reproduction recomputes the counts
from the committed rows with the pinned evaluator.
The approved V10 header, proof-set kinds and historical vectors retain
their encodings.

## Field-table types

- **EVTX EventID and LogonType.** For exact reviewed paths in a provider- and
  channel-scoped variant, `conversion = "evtx_event_id"` admits one to five
  ASCII decimal digits in the unsigned 16-bit range.
  `conversion = "evtx_logon_type"` admits one to three digits in the unsigned
  8-bit range. A missing field remains absent. Other shapes and overflow are
  rejected. Rule literals are typed integers. Source-class selectors still
  compare exact original literals. [SigmaHQ Windows process-creation guide](https://github.com/SigmaHQ/sigma/blob/master/documentation/logsource-guides/windows/category/process_creation.md)
- **Microsoft 365 Parameters.** The Exchange AuditData `Parameters` binding
  uses `value_type = "pair_list"`. Each exact predicate has both `Name` and
  `Value` and matches a single object. The initial bound is 128 pairs with
  UTF-8 text of at most 512 bytes for the name and 4,096 bytes for the value.
  An unsupported value type or shape is explicit. The pair binding rejects
  scalar predicates and modifiers. The negative vector puts the requested name
  and value in different entries.
- **Defender Image and ParentImage.** Use `conversion = "defender_full_path"`
  with explicit primary field and `basename_path`. Inspect only enrolled
  `DeviceProcessEvents` with Windows platform evidence. Return the raw
  `FolderPath` or `InitiatingProcessFolderPath` when it is a lexical absolute
  Windows path and its final component equals the corresponding filename
  using ASCII case-insensitive comparison. Require both fields, a complete
  basename, and valid components. Leave the alias absent for directory-only
  values, missing or mismatching filenames and malformed paths. Preserve the
  original folder and filename bindings for investigation. There is no join.
  Prove Windows from captured platform metadata for the source row.
  Microsoft's pinned CSV shows that all 46 process rows contain the
  corresponding executable basename in both path columns. The second
  published example has directory-only `FolderPath` in all 30 rows with both
  fields. The branch tests both shapes with synthetic values. [Microsoft Sentinel process-event CSV](https://github.com/Azure/Azure-Sentinel/blob/6c8d75ee0ba2d1cc438c3244b492f0de82c324a3/Sample%20Data/ASIM/Microsoft_M365%20Defender%20for%20Endpoint_ProcessEvent_IngestedLogs.csv) · [Advanced Hunting export-shaped sample](https://github.com/iamkaushiksaha/azure-security/blob/main/sentinel/tables/DeviceProcessEvents/DeviceProcessEvents_sample.csv) · [pySigma Defender field mapping](https://github.com/WildDogOne/pySigma-backend-microsoft365defender)

## Independent vectors

The fixture contains representative bindings for the changed classes with
fixed synthetic implementation identities. Production fills in the exact
reviewed identities of the release. The wire uses the existing field-table
object domain and UTF-8 strings with big-endian u32 byte lengths. The table ID is
`irmind-sigma-source-coverage`, the new table version is `v2` and the fixture's
TOML bytes enter the proof verbatim. Cases, receipts, export V10 object slots
and the wire kind have their existing encodings.

The standard-library generator reproduces the unchanged field-table object
and the revised retained-text vectors. It covers a synthetic 33-address
`X-Forwarded-For` request and its resulting audit row, malformed and
duplicate IPs, wrong value types and GKE status ranges. The result and receipt
vectors include partial coverage alongside a legitimate match on a different
row. Defender, EVTX and M365 vectors retain their approved bytes. [TOML input](../../crates/testkit/fixtures/contracts/sigma_exact_source_fields.toml) · [Vectors](../../crates/testkit/fixtures/contracts/sigma_exact_source_fields.json) · [Generator](../../crates/testkit/fixtures/contracts/sigma_exact_source_fields.py)

```sh
python3 -B crates/testkit/fixtures/contracts/sigma_exact_source_fields.py \
  | diff - crates/testkit/fixtures/contracts/sigma_exact_source_fields.json
```

After vector review, the implementation tests must also cover
`preserve_order`, exact row verification, cancellation and the
2,000-rule release benchmark. The stored source values remain tainted.
