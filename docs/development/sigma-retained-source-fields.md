# Exact Sigma source fields for v0.7

**Status** · Proposed. The published V10 receipt and export layouts retain their approved encodings. This proposal changes the retained Parquet text for specific mappings and extends the versioned Sigma field table and its predicate contract.

## Kubernetes and GKE

Clustered audit mappings currently write the bounded common projection in the existing Parquet `text` column. The full list of client IPs and the GKE gRPC status are unavailable in that projection. The separate `source.ip` scalar authenticates one address and cannot satisfy a rule over the original `sourceIPs` list.

Use the existing UTF-8 `text` column with a versioned envelope, initially `irmind-kubernetes-sigma-projection-v1`. Retain the current normalized projection and a separate, bounded object containing only the approved original paths. Preserve `sourceIPs` as the list of strict IP values with their original order in Kubernetes, EKS and AKS. Preserve `protoPayload.status.code` as the original optional integer in GKE. A missing field remains absent. The envelope carries the original paths needed to distinguish the two status contracts. Embedded response and request objects stay in the original source.

Use a new mapping implementation identity for each affected mapping. The Parquet schema, source and row references, sealing and V10 object slots stay the same. The existing source and mapping commitments authenticate the changed row bytes. Readers of the old projection may still verify its signatures and report the missing fields.

## Field-table types

- **EVTX EventID and LogonType.** Use a checked decimal-text conversion declared for the exact native path. Accept an integer Sigma literal against the converted value. Bound the digits and range for each field, keep missing values absent and reject other shapes. Add separate field-table fixtures for a correctly typed value, the wrong provider or channel, a miss and numeric overflow. [SigmaHQ Windows process-creation guide](https://github.com/SigmaHQ/sigma/blob/master/documentation/logsource-guides/windows/category/process_creation.md)
- **Microsoft 365 Parameters.** Use an exact list of bounded name/value pairs from the original AuditData object. An exact pair predicate binds both members from the same object. A rule expecting a scalar string, arbitrary object traversal or an unsupported modifier is reported as skipped. Test two parameter entries where independent matches for the name and value would produce a false hit.
- **Defender Image and ParentImage.** Assemble a lexical Windows path from the documented folder and filename fields only in an enrolled DeviceProcessEvents class with explicit Windows platform evidence. Apply bounded validation, preserve the folder/filename fields, and leave the alias absent for malformed paths or missing segments. Use DeviceInfo-derived platform metadata only when it is already part of the analyst's captured source row. [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) · [DeviceInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)

Use a new reviewed table version for these operations. Export the exact reviewed table and retain the same receipt fields. Before implementation, independently generate vectors for the new table and the retained projection. Then cover invalid shapes, inconsistent inventories, cancellation, `preserve_order`, exact row verification and the 2,000-rule synthetic release benchmark. Source data stays tainted and under the existing size and work ceilings.
