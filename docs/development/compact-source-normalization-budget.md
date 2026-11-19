# Compact-source normalization budgets

[Español](../es/development/compact-source-normalization-budget.md)

## Scope and measurements

This proposal changes resource admission for the new VPC flow decoder. It does
not change signed formats, mapping semantics, stable order or source verification.
The additive preflight is implemented alongside the new decoder; existing decoders retain their admission.

The optimized 1 GiB compact VPC ingestion test fails with
`StorageNormalizedStagingSpace`. The source has a native column header and repeats
a 131-byte synthetic flow record; it is not padded to reduce expansion. This is a
failed end-to-end measurement, not a throughput result.

The production `RecordRow::from_mapping` projection and `EncodedSize` serializer
produce these counts in a release-only diagnostic:

| Synthetic source | Source bytes | Normalized bytes | Expansion |
| --- | ---: | ---: | ---: |
| Custom VPC flow, one data row (header excluded from denominator) | 131 | 2,898 | 22.122× |
| Standard v2 VPC flow, one row | 107 | 2,445 | 22.850× |
| Azure VNet fixture | 866 | 9,240 | 10.670× |
| Azure NSG fixture | 583 | 8,720 | 14.957× |
| GCP VPC fixture | 2,434 | 11,071 | 4.548× |

These fixture ratios are representation measurements, not throughput benchmarks
or worst-case bounds. The normalized staging representation includes original
searchable fields, validated common context, role/scoped observations, source
identity, ordering metadata and partition routing. They must not be removed merely
to fit the allowance. Record numbers and offsets can increase serialized size.

Reproduce the diagnostic and the currently failing benchmark:

```sh
cargo test --release -p irmind-infra compact_flow_normalized_expansion -- --ignored --nocapture
cargo test --release -p irmind --test identity_ingest one_gib_release_throughput -- --ignored --nocapture
```

## Current admission

For each source the allowance is `physical_bytes * 16 + 64 MiB`. The group
preflight requires the sum of allowances plus a 64 MiB margin in the case data
filesystem. Each serialized normalized row is limited to 64 MiB. The allowance is
charged in both the direct ordered path and the disordered spool path, even when
no normalized spool is written. The compressed physical size is currently the
basis for gzip sources as well. A quota failure rolls back the source/group;
no partial source manifest may be published.

## Proposed additive decoder contract

Add one optional `SourceDecoder` method, with no change to existing implementations:

```rust
fn normalized_source_budget(
    &self,
    file: &mut std::fs::File,
    cancel: &CancellationToken,
) -> Result<Option<NormalizedSourceBudget>, AppError> {
    Ok(None)
}
```

`None` preserves the existing 16× physical-byte admission. The new bounded type
has private fields and validated constructors: an uncompressed byte count at most
50 GiB and a closed expansion profile, initially only `CompactFlow32`. Its
allowance is `decoded_bytes * 32 + 64 MiB`, using checked arithmetic. There is no
unlimited value, model argument or free-text multiplier. Only the new VPC decoder
selects this profile. Other decoders retain their existing admission unchanged.

For plain VPC input, the decoder uses the opened file's length. For gzip, it counts
decoded bytes in a separate bounded streaming preflight with its existing gzip
implementation. The preflight validates all gzip members/checksums, caps both
compressed and decoded input at the existing 50 GiB source limit, checks cancellation
between bounded reads, and writes no evidence or normalized data. It never relies
on gzip ISIZE, a filename or a claimed expansion ratio. This extra read is a
measurable gzip cost, not hidden in a throughput claim.

The coordinator owns rewinding the same opened file before and after the optional
method, validating the result and checking group free space before actual staging.
The normal initial hash and final source-unchanged check still authenticate the
actual ingestion. A changed source or an underestimated budget fails and rolls
back; preflight does not authorize accepting changed bytes. File access remains
read-only. No new `LargeCaseStore` method or external dependency is needed.

## Resource and compatibility effects

This explicitly raises the normalized-byte allowance for the new VPC decoder,
from 16× physical input to 32× decoded input. It also raises its disk reservation;
1 GiB of decoded input has a roughly 32 GiB normalized allowance. The existing complete-group formula also reserves sort-fallback scratch, so a one-source group needs roughly 64 GiB plus margins. Insufficient case
filesystem space must fail before normalization. High-compression gzip inputs no
longer receive a reservation based only on their smaller compressed file size.
An input whose actual normalized representation exceeds the new allowance still
fails completely. This does not promise acceptance of every syntactically valid
input. The quota is enforced equally in direct and sorting paths.

The 4 MiB decoded-record limit, field/node/depth bounds, ten-million-record limit,
64 MiB normalized-row limit, queue/writer budgets, source limits, taint, ContentGuard,
provenance, cancellation, rollback and hash/signature checks remain unchanged.
No evidence goes to the system temporary directory. Current canonical and physical
golden bytes remain unchanged; a budget changes admission, not emitted records.
The new decoder identity already identifies the implementation used for a source.

## Validation before integration

- A decoder using the default method has identical reservations and quota failures.
- Exact-boundary and overflow tests for the closed budget constructor and arithmetic.
- Plain/gzip equivalent source bytes request the same normalized allowance; multiple
  gzip members, a corrupt trailer and a decompression-size violation fail clearly.
- Cancellation during preflight writes no spool, artifact or signed source manifest.
- Insufficient space prevents normalized writes; an actual quota overrun rolls back
  completely in ordered and disordered paths, including object-storage downloads.
- Source mutation cannot publish records with a stale signed source hash; test both replacement after preflight and mutation during actual ingestion.
- Compare output bytes and commitments with 1/2/4/N workers and all current goldens.
- Repeat the unpadded 1 GiB VPC release benchmark, including gzip separately, then
  report successful throughput, peak memory and case-local staging peak. Recheck
  1/64/1,024/1,025 host cardinalities and the overflow host's queryability.
