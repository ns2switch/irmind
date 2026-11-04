# Explicit Parquet migration and export V5 boundaries

This page is for maintainers implementing explicit migration of open cases and mixed-version exports. It complements the [artifact V2 design](parquet-artifact-v2-design.md#compatibility-and-migration) without changing existing source, audit-entry or seal encodings.

## Application boundary

Migration is an attended analyst action shared by the TUI and automation CLI. It is not an agent tool. Its application workflow locks the case, rejects sealed cases, verifies the complete chain and artifact inventory, resolves pinned source parsers, prepares derived replacements, signs one complete replacement set, commits the audit batch and verifies the result.

Local preparation remains synchronous and runs inside `spawn_blocking`. Cancellation is checked between source, record and output batches. Preparation cannot publish a new active catalog by itself.

## Additive preparation contract

Retained originals and derived-file paths belong to the local adapter. Reusing the legacy buffered-evidence method would require loading whole originals; making the application construct storage paths would break that boundary. Add a preparation operation that receives the verified case snapshot and returns an adapter-owned staging handle:

```rust
pub struct ArtifactMigrationRequest<'a> {
    pub case_id: &'a CaseId,
    pub source_root: Option<&'a Path>,
    pub signed_entries: &'a [SignedEntry],
    pub parser: &'a dyn StreamingEventParser,
    pub limits: PartitionLimits,
}

// New LargeCaseStore method; existing methods remain unchanged.
fn prepare_artifact_migration(
    &self,
    request: ArtifactMigrationRequest<'_>,
    cancel: &CancellationToken,
) -> Result<Box<dyn PreparedArtifactMigration>, AppError>;

pub trait PreparedArtifactMigration: Send {
    fn artifacts(&self) -> &[ParquetArtifactV2];
    fn record(&self) -> &ParquetMigrationV1;
    fn publish(&mut self, cancel: &CancellationToken) -> Result<(), AppError>;
    fn retain_committed(&mut self);
}
```

The default method reports unsupported migration. It never delegates to V1 preparation or silently reports a successful no-op. The handle exposes signable metadata, not private adapter paths or original content. `ParquetMigrationV1` is the domain record specified by the design's `irmind-parquet-migration-v1\0` payload: source identities, original/replacement parser mappings, old/new artifact hashes, builder and time semantics.

The adapter resolves retained copies or the supplied source root, verifies original hashes and stages deterministic V2 replacements in the case's private directory. URI originals require a verified local source obtained through the existing authorized object-source workflow; the local adapter never introduces a network path. Missing, changed or unavailable originals produce an explicit error.

Preparation verifies staged artifact hashes and reconstruction, record identities/counts and non-time semantics. A change beyond timestamp precision is not part of this migration. Already generic V2 inputs seed the existing signed partition allocation; the same source cannot acquire slots through unsigned work.

## Staging lifecycle

1. Prepare and verify privately. The old catalog stays active.
2. The application validates the domain record and signs the complete new artifact/migration batch before publication.
3. Publish the verified files while holding the case lock. They become queryable only when the corresponding signed batch commits.
4. Append all replacement metadata and the migration record atomically through `AuditLog::append_batch`.
5. Mark the handle retained and verify the resulting chain/catalog.

Dropping an uncommitted handle removes only its owned staged/generated files; it never deletes historical signed artifacts. Recovery distinguishes a committed complete set from abandoned preparation through the signed chain. A process interruption cannot authorize a partial replacement. Temporary storage remains case-local, privately permissioned and preflighted for space.

## Versioned export contract

Keep the existing V4 method and its V1-only semantics. Add one local synchronous method with the same input shape:

```rust
fn export_case_v5(
    &self,
    id: &CaseId,
    path: &Path,
    source_root: Option<&Path>,
    include_originals: bool,
    cancel: &CancellationToken,
) -> Result<String, AppError>;
```

Its default reports unsupported export V5. The application selects V5 for a case containing V2 artifacts or migration records, and preserves V3/V4 behavior for older cases. UI and CLI invoke the same application selection. No presentation code constructs an archive.

V5 uses `IRMIND-EXPORT-V5\0`, a typed version-5 header and the existing bounded streaming framing. It carries both artifact envelopes, original and replacement metadata, migration records, and optional originals. Verification dispatches explicitly by magic/version, requires the expected analyst-key fingerprint when supplied, and uses only public verification keys. V4 remains strict and rejects unsupported new payloads.

The existing seal challenge and analyst fingerprint remain unchanged. The seal manifest includes all required source/artifact hashes across both generations, with historical byte compatibility for V1-only cases.

## Implementation checks

- Independent golden migration bytes and V5 frames; historical goldens unchanged.
- Open-case migration with retained and in-place originals, and pinned mixed source parsers.
- Complete original/hash/count/record comparison before replacing an active generation.
- Missing or changed originals, unknown parsers, sealed cases, cancellation and interruption boundaries.
- Shared active-set validation for application, query catalog, seal and export verification.
- Mixed-generation queries retain result/time/hop limits and explicit precision markers.
- V3/V4 verification remains compatible; V5 verifies without a keystore and rejects malformed or incomplete packages.
- Extend canonical/export fuzz targets and retain all guard/provenance boundaries.

Default TUI writing switches to V2 only with the completed migration/export implementation. Host/default and 15 GB temporary-disk measurements remain in the subsequent release-profile benchmark work.
