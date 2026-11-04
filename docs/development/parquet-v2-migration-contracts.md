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

Preparation verifies staged artifact hashes and reconstruction, record identities/counts and non-time semantics. A change beyond timestamp precision is not part of this migration. The precision-only operation keeps each parser ID and version pinned; it does not select parser upgrades automatically. Already generic V2 inputs seed the existing signed partition allocation; the same source cannot acquire slots through unsigned work.

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

Default TUI writing switches to V2 only after migration/export and the release-profile benchmarks are integrated. Host/default and 15 GB temporary-disk measurements remain in the subsequent release-profile benchmark work.


## Bounded canonical migration record

The new record binds complete signed inventories with counted SHA-256 commitments. This keeps one atomic migration within the existing 16 KiB payload ceiling even for cases with thousands of artifacts. Individual source and artifact envelopes remain in the signed chain and are not replaced by these commitments.

After the `irmind-parquet-migration-v1` NUL tag, fields are:

1. Source-set commitment, previous-artifact commitment and replacement-artifact commitment.
2. Up to 32 parser transitions, sorted uniquely by old ID/version and new ID/version. Each transition carries the commitment to its source subset. Subset counts must cover the source count exactly.
3. Builder version and time-semantics identifier.

A set commitment is a big-endian `u64` count followed by a length-prefixed lowercase SHA-256. Source-set hashing uses `irmind-migration-sources-v1` + NUL, the count, and length-prefixed source hashes in lexical order. Artifact-set hashing uses `irmind-migration-artifacts-v1` + NUL, the count, and length-prefixed complete canonical artifact payloads ordered by relative path. These are the UTF-8 bytes of the lowercase hex string returned by `ParquetArtifact::encode`, as stored in the signed entry, not the decoded envelope bytes. Including the full envelope distinguishes equal-content files with different signed metadata. Strings and counts use the existing canonical encoding; unknown or trailing bytes are invalid.

The migration directory uses `migration-<previous-artifact-commitment>`. Every replacement keeps bounded supersession references to the previous artifacts of the same source and schema family. The shared lineage interpreter recomputes the complete commitments, validates source/family coverage and parser mapping, and retires paths only after accepting the final analyst record. The independent [golden payload](../../crates/domain/tests/fixtures/parquet-migration-v1.hex) fixes this new encoding without modifying any historical golden.


## Bounded V2 seal inventory

Cases containing V2 artifacts use a fixed-size `SealInventoryV2` descriptor in the existing signed seal event. V1-only cases retain their explicit inventory byte for byte. The seal challenge and analyst fingerprint do not change.

The descriptor is `irmind-seal-inventory-v2` + NUL, a big-endian `u64` item count, and a length-prefixed lowercase SHA-256. It uses the existing canonical hex envelope and strict decoding. The independent [golden](../../crates/domain/tests/fixtures/seal-inventory-v2.hex) and [SHA-256](../../crates/domain/tests/fixtures/seal-inventory-v2.sha256) pin the bytes; the alternate JSON-map CI job checks them too.

Items have a closed kind: legacy copied evidence (0), source manifest (1), or artifact manifest (2). Their identity is respectively the evidence hash, signed source name/URI, or relative artifact path. Each item hash is SHA-256 over `irmind-seal-inventory-item-v2` + NUL, its one-byte kind, length-prefixed UTF-8 identity, and length-prefixed canonical payload. Evidence uses its lowercase hash as payload; manifests use the canonical lowercase hex envelope. Different paths with identical file contents remain distinct items.

The root hash covers `irmind-seal-inventory-items-v2` + NUL, the `u64` count, and every item in strict `(kind, identity)` byte order. Each root item contains the kind, length-prefixed identity and fixed 32-byte item digest. Counts are bounded; duplicates and noncanonical order are invalid. All historical and active artifact manifests participate. The descriptor is not a substitute for those manifests or the case chain.

Verification authenticates the entire ordered audit chain and the separate seal signature, reconstructs the inventory from its signed entries and verified copied-evidence frames, and compares both count and root. A standalone descriptor never verifies a case. Metadata tests exercise 20,000 and 100,000 artifacts, including insertion, removal, reordering and changed bytes. Smaller real-signature archive tests also reject an incorrect root or counter even when signed again with the synthetic analyst key.

## V5 derived-file frames

After the existing operation frames, V5 exports include the complete derived-file set named in the case chain, including historical generations. A `u64` count precedes files in strict relative-path order. Each file has one bounded JSON metadata frame (`path`, `sha256`, `size`) and exactly that many raw bytes. The verifier matches every field to the authenticated artifact manifest and hashes the body in bounded chunks. Missing, duplicate, reordered, changed, extra or truncated files invalidate verification. Original log inclusion remains optional and independent of derived files.

All metadata frames retain the 1 MiB ceiling. Only the historical empty-artifact V5 seed may end at the previous section boundary; a case with artifacts cannot omit the derived-file section. V3/V4 framing and historical golden bytes remain unchanged. Export verification requires only public keys and the expected fingerprint when supplied.
