# Exact Sigma source fields for v0.7

**Status** · Design approved. Wire vectors submitted for review. The published V10 receipt and export layouts retain their approved encodings. This proposal changes the retained Parquet text for specific mappings and extends the versioned Sigma field table and its predicate contract.

## Kubernetes and GKE

Clustered audit mappings currently write the bounded common projection in the existing Parquet `text` column. The full list of client IPs and the GKE gRPC status are unavailable in that projection. The separate `source.ip` scalar authenticates one address and cannot satisfy a rule over the original `sourceIPs` list.

Use the existing UTF-8 `text` column. The compact JSON envelope has exactly
three keys in lexical order and no surrounding whitespace or final newline.
`common` contains the canonical CommonEvent JSON object. `format` is
`irmind-kubernetes-sigma-projection-v1`. `original` contains just the
reviewed original paths and uses lexical object-key order recursively.

- Native Kubernetes retains a present `sourceIPs` array at
  `original.sourceIPs`. EKS and AKS use `original.audit_event.sourceIPs`.
  Keep at most 32 IP address strings of no more than 45 UTF-8 bytes each.
  Preserve source order and spelling. Compare parsed address values for
  duplicates, so alternate IPv6 spellings of the same address are duplicates.
  Reject the projection if the field is present and the array is oversized or
  includes a duplicate, a malformed IP or a non-string entry. An empty array
  remains an empty array. A missing field remains absent.
- GKE retains a present `protoPayload.status.code` integer at
  `original.protoPayload.status.code`. Accept a nonnegative 32-bit signed
  status code. Reject unexpected types and out-of-range values. An absent
  status code stays absent. The gRPC code remains distinct from the HTTP
  status contract of native Kubernetes.
- Cap the entire encoded envelope at 65,536 bytes, the current Sigma original
  row ceiling. Oversize projections and invalid entries must surface as row
  rejections. They must not be represented as an absent field or a shortened
  list in a row presented to Sigma. Request and response bodies stay in the
  original source.

Use a new mapping implementation identity for each affected mapping. The Parquet schema, source and row references, sealing and V10 object slots stay the same. The existing source and mapping commitments authenticate the changed row bytes. Readers of the old projection may still verify its signatures and report the missing fields.

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

The standard-library generator reproduces the binary table object's hex and
SHA-256 and each canonical retained-text example. It includes the rejection of
invalid, repeated and excess IPs, both Defender path shapes, EVTX numeric
overflow and the M365 cross-pair miss. [TOML input](../../crates/testkit/fixtures/contracts/sigma_exact_source_fields.toml) · [Vectors](../../crates/testkit/fixtures/contracts/sigma_exact_source_fields.json) · [Generator](../../crates/testkit/fixtures/contracts/sigma_exact_source_fields.py)

```sh
python3 -B crates/testkit/fixtures/contracts/sigma_exact_source_fields.py \
  | diff - crates/testkit/fixtures/contracts/sigma_exact_source_fields.json
```

After vector review, the implementation tests must also cover
`preserve_order`, exact row verification, cancellation and the
2,000-rule release benchmark. The stored source values remain tainted.
