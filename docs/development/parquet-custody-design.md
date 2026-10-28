# Large-case custody format

This page is for maintainers reviewing the versioned large-case custody format. The signed audit encoding and seal challenge remain unchanged. Legacy v3 exports remain verifiable; cases with source manifests use streaming v4 packages.

## Legacy constraint

The current ingest use case accepts a byte slice of at most 50 MB, writes a content-addressed local copy, and signs an `EvidenceIngested` entry. Verification expects that copy. Export v3 is a JSON document capped at 128 MiB and requires every audit evidence hash to be present in it. These rules cannot represent an uncopied 15–500 GB source or a manifest-only export.

## Signed records

Add two versioned event payloads to the existing case audit chain, without changing the canonical `SignedEntry` encoding or existing event names:

- `SourceManifestV1`: normalized source identity (relative path under an explicitly selected root, or object URI), byte length, UTC modification instant when available, source version and provider checksum when available, and IRMind SHA-256. The enclosing audit entry supplies the case ID. A copy flag states whether a local original was stored. The original is hashed in a bounded streaming pass. The record is signed by the active case signer as part of the audit chain. The path or URI is data, never a command or SQL fragment.
- `ParquetArtifactV1`: relative artifact path, byte length, SHA-256, parser and schema versions, partition keys, and sorted hashes of the source records that produced it. A hash of its canonical payload joins the same chain. An artifact is derived data, never a substitute for a source hash.

Both payloads use a domain-tagged, length-prefixed binary encoding carried as ASCII in the current signed `payload` field. Fields, optionality, byte order, path separators, and sorting are fixed. Unknown versions fail closed. No new record can reinterpret a legacy `EvidenceIngested` entry. The existing case seal covers the final audit hash and therefore the new records; its signature challenge stays unchanged.

Each file's source manifest and newly derived artifact records are signed first, then inserted as one SQLite transaction. An insert failure rolls back every record in that batch. Prepared Parquet files may remain on disk without a signed reference; retry verifies their hashes before reusing them.

Object URIs contain only provider, bucket or container, and object key. Query strings, user information, bearer tokens, and SAS tokens are rejected. Source names may themselves contain sensitive information, so the export confirmation names this metadata as part of the package; the model sees only guarded, redacted source labels.

For local files, open without following symlinks, hash through the opened handle, seek back, and hash again while parsing. Commit neither record nor Parquet artifact unless both hashes and stable file identity agree. This catches a source change between the two passes. Cloud objects are read by explicit version or conditional request when available and hashed during the conversion pass. Temporary derived files are renamed into place only after the hash and parser succeed; cancellation deletes them.

## Verification and export

Full source verification reopens every source and streams a SHA-256 check against the manifest. Explicit sampled verification uses a fresh random selection and reports the sample size, failed sources, and that unchecked sources have **not** been verified. A missing source, changed hash or modification time, or unsafe path is reported as a failed check. Provider checksums are diagnostic metadata; they never replace IRMind SHA-256.

Opening a large case verifies the signed chain and manifest structure without silently claiming to have re-read hundreds of gigabytes. Full or sampled source verification is an explicit analyst action. A failed source check marks the affected source inconsistent and prevents it from being presented as verified evidence; the signed case metadata remains available for inspection.

`verify_graph` checks each generated Parquet artifact hash, its source linkage, and a reproducible rebuild. It never reads arbitrary Parquet or raw evidence chosen by a model. A canceled rebuild leaves the last verified version usable or fails closed.

Neighbor queries read only signed, hash-checked Parquet. They inspect at most 4,096 records containing the selected entity and explicitly label the result as partial when more records match. This bounds the self-join for ubiquitous entities; counts in a partial result apply only to the selected records, so the analyst must narrow the entity before treating them as case-wide counts.

A typed optional query filter selects date, account or project, and region partitions from signed artifact metadata before verification and scanning. An exact UTC predicate also filters records within boundary dates. Policy rejects model filters outside the case or organization scope; local callers enforce the case scope too. The TUI, model tool catalog, and CLI expose the same fields. Filtering a case that still contains legacy graph records fails clearly until migration completes.

Migration first fully verifies the legacy chain and every copied evidence blob. For an open case, it appends the new artifact records only after conversion succeeds, then fully verifies again. A sealed case cannot acquire case-chain entries. Its derived artifact records instead enter the separate signed operational chain as `sealed-parquet-artifact-v1`, bound to the existing final seal hash. The seal and original case chain do not change. Export v4 carries and verifies the complete operational chain; an unmigrated sealed case can still use v3.

Export v4 is a bounded-memory, length-prefixed streaming package containing the audit chain, signed source manifest and Parquet metadata, seal, signed operational chain, and optionally the original bytes. `verify-export` validates the signatures and package structure without a keyring. When originals are omitted it reports **manifest verified; source bytes unavailable**, never **evidence verified**. Legacy v3 packages retain their existing verifier. Package paths are relative slash-separated names and cannot contain traversal or symlinks.

The export-verification result reports format version, signed source count, verified source-byte count, and sources whose bytes are unavailable in the package. The legacy v3 call remains available for compatibility.

## Benchmark storage

A [standard public GitHub Linux runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) has 14 GB of SSD, so a 15 GB raw corpus cannot be materialized alongside the build and Parquet output. The 15 GB benchmark will generate deterministic CloudTrail-shaped records directly into the streaming input during the job and discard each chunk after hashing and conversion. It measures the local pipeline, not object-store network latency or a physical source-disk read. A smaller 1 GB file corpus remains the check for local filesystem behavior.

## Guarantee change

An original copy makes offline re-verification and a portable evidence export possible. A manifest without that copy proves what IRMind observed and signed at ingestion time, but later byte verification depends on the original still being reachable and unchanged. A sampled check provides evidence only for the selected sources. Cloud object version identifiers improve repeatability but are not universal; without a stable version, verification compares the current object to the signed hash. No local signature alone proves that the analyst did not replace the entire chain with their own key.
