# Approved deterministic partition preparation

This document is for the analyst reviewing the exact application boundary needed for artifact-V2 step (c). The [approved design](parquet-artifact-v2-design.md#generic-scope-partitions) already defines normalization, signed caps, overflow and safe paths. This proposal does not implement them or change a signed format. It follows the [mixed reader/writer](https://github.com/ns2switch/irmind/pull/168).

## Why per-file preparation needs a batch boundary

Today `LargeCaseStore::prepare_local` parses and publishes one source independently, and the application prepares four sources concurrently. Sharing an allocation mutex inside the adapter would assign the first 64 host slots by worker completion. It could also consume unsigned slots after cancellation. Both violate the approved deterministic replay rule.

Add one synchronous, cancelable batch operation. The application supplies the already verified committed artifact snapshot under the existing case lock. The adapter stages up to four bounded parser streams privately, then assigns partitions in sorted source order and stable record order. It can parse independently in parallel; a bounded coordinator owns slot allocation. Only existing signed artifacts and the current canonical batch influence assignments. No global allocation state or new custody dispatcher is introduced.

## Proposed additive storage contract

```rust
pub struct PartitionLimits {
    pub account: u16,
    pub region: u16,
    pub host: u16,
}

pub struct LocalBatchRequest<'a> {
    pub case_id: &'a CaseId,
    pub source_root: &'a Path,
    pub relative_paths: &'a [String],
    pub copy_original: bool,
    pub parser: &'a dyn StreamingEventParser,
    pub committed_artifacts: &'a [ParquetArtifact],
    pub limits: PartitionLimits,
}

// Added to LargeCaseStore; existing methods keep their signatures.
fn prepare_local_batch(
    &self,
    request: LocalBatchRequest<'_>,
    cancel: &CancellationToken,
) -> Result<Vec<PreparedSource>, AppError>;
```

The default implementation delegates to existing V1 per-source preparation and rejects V2 output instead of claiming that an unallocated source satisfies the partition contract. The Parquet adapter overrides it. The application uses this operation for ordinary local ingestion and object-storage conversion after the existing private download spool; downloading, authorization, ETag/hash checks and source signing stay on their current paths. A one-object conversion is a one-source batch.

`PartitionLimits` validates 1–1,024 for every active key. Host starts at 64, pending the approved benchmark; account and region start at 1,024. The tuple ceiling remains the already approved 4,096 per date. Effective caps are signed in the existing V2 envelope fields. An existing committed allocation is never silently remapped by a settings change. Allocations derived from signed history are authoritative for that case/key; a changed policy can affect new allocations only through an explicit supported change or migration.

Prepared results retain canonical source order. Existing atomic source-plus-artifact audit batches commit one source at a time. If signing a source fails, later prepared sources are never committed. A subsequent attempt reconstructs its slots solely from committed history, so cancelled or unsigned work consumes none. Temporary normalized streams live under the private case directory and are removed on success, error, cancellation and orphan recovery. Rebuild uses the same source order, caps and builder; it verifies ordinary assignments and every overflow reason.

## Parser-owned capabilities

Add a pure optional method to `StreamingEventParser`:

```rust
pub enum PartitionProfile {
    Unpartitioned,
    CloudAccountRegion,
    EndpointHost,
}

fn partition_profile(&self, record: &GraphRecord) -> PartitionProfile {
    PartitionProfile::Unpartitioned
}
```

This closed profile chooses supported keys, never arbitrary strings. Native cloud records select account/region; endpoint/network records select host; absent values remain absent. The JSON module can distinguish its supported cloud record shapes from generic host-bearing JSON without making every caller inspect a dialect. Other modules declare their profile locally. The declarative module derives it only from its signed approved definition and supported mapping.

Capabilities are pinned by the native parser identity/version together with the signed builder revision. Historical V1 callbacks and normalized output stay unchanged. The date-only precise writer from step (b) retains its builder and reconstruction behavior; the partitioned writer gets a distinct builder revision. A later change to a parser profile requires a reviewed capability/builder revision rather than reinterpreting existing artifacts. No reserved `tenant` or `cluster` profile is activated.

## Additive host query selector

Keep `GraphQueryFilter::parse` and every `EvidenceGraph` signature unchanged. Add a checked `parse_with_host` constructor and a borrowed `host()` accessor. Existing callers default to no host selector. Tool schemas and the TUI accept the new optional host field through the same validated filter.

A host selector is checked against case and organization ceilings and matched against actual normalized row values. Partition normalization only helps pruning. Missing keys, legacy metadata and applicable overflow remain candidates; an unknown selector never becomes a wildcard. Hash verification, projection, exact time filters, sampling, hop/expansion limits and the 10-second path budget remain intact.

## One direct dependency, no new lockfile package

Add `unicode-normalization = "=0.1.26"` directly to `irmind-infra` for the approved NFKC/Unicode-18 policy. That exact package and its dependencies already exist in `Cargo.lock` through `irmind-security`; this adds a direct production edge, not a package or version. Reuse its pinned Unicode data, check the policy identifier and reject unsupported changes. Keep normalization bounded before and after expansion; only generated hashes or typed overflow components become paths.

An adapter cannot depend on `irmind-security` just to borrow its normalization implementation. Routing partition names through `ContentGuard` would also mix redaction/detection rules with deterministic bucket naming. An ASCII-only implementation without this dependency would not satisfy the approved NFKC requirement. The recommended option is the direct, already locked normalization package; no new parser or remote module is proposed.

## Implementation requirements

The batch method, closed profile, checked host selector and normalizer dependency are defined in [PR #169](https://github.com/ns2switch/irmind/pull/169). The implementation is a separate PR; this document changes no signed bytes.

Derive the normalization policy identifier from `unicode_normalization::UNICODE_VERSION`. A regression test pins the approved Unicode version and identifier. Updating the crate's Unicode tables must fail that test and require a reviewed new policy rather than silently changing historical allocation.

Before staging any normalized batch, check available space in the private case directory against a bounded staging reservation plus a safety margin. At most four sources are staged. Exhaustion fails before copying with a clear error. Bound actual spool writes by the reservation, recover orphans, and measure peak temporary disk use in the 15 GB release benchmark.

Treat model-supplied hosts as untrusted tool arguments. Reject paths, controls and strings impersonating typed overflow; never turn an invalid host into an absent filter. Exact row matching and both case and organization ceilings remain mandatory.

Implementation must prove identical allocations under reordered workers, no slots consumed by rollback/cancellation, signed reconstruction of overflow and exact filters across missing/overflow/legacy buckets. Test normalization collisions, forbidden controls and path syntax, safe hash paths, 64/1,024/1,025 hosts, per-date tuple overflow and bounded writers/files. Keep the existing V1 and step-(b) physical goldens unchanged. The release benchmark selects the final host default; it does not relax a budget to make a measurement pass.
