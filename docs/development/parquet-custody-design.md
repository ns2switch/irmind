# Proposed large-case custody format

This page is for maintainers reviewing the signed-format change needed by phase P. It is a proposal, not an implemented format. The existing signed audit encoding, seal challenge, and v3 export remain valid for old cases.

## Current constraint

The current ingest use case accepts a byte slice of at most 50 MB, writes a content-addressed local copy, and signs an `EvidenceIngested` entry. Verification expects that copy. Export v3 is a JSON document capped at 128 MiB and requires every audit evidence hash to be present in it. These rules cannot represent an uncopied 15–500 GB source or a manifest-only export.

## Proposed signed records

Add two versioned event payloads to the existing case audit chain, without changing the canonical `SignedEntry` encoding or existing event names:

- `SourceManifestV1`: case ID, normalized source identity (relative path under an explicitly selected root, or object URI), byte length, UTC modification instant when available, source version and provider checksum when available, and IRMind SHA-256. A copy flag states whether a local original was stored. The original is hashed in a bounded streaming pass. The record is signed by the active case signer as part of the audit chain. The path or URI is data, never a command or SQL fragment.
- `ParquetArtifactV1`: relative artifact path, byte length, SHA-256, parser and schema versions, partition keys, and sorted hashes of the source records that produced it. A hash of its canonical payload joins the same chain. An artifact is derived data, never a substitute for a source hash.

Both payloads use a domain-tagged, length-prefixed binary encoding carried as ASCII in the current signed `payload` field. Fields, optionality, byte order, path separators, and sorting are fixed. Unknown versions fail closed. No new record can reinterpret a legacy `EvidenceIngested` entry. The existing case seal covers the final audit hash and therefore the new records; its signature challenge stays unchanged.

## Verification and export

Full source verification reopens every source and streams a SHA-256 check against the manifest. Explicit sampled verification uses a fresh random selection and reports the sample size, failed sources, and that unchecked sources have **not** been verified. A missing source, unavailable object version, changed hash, or unsafe path is reported as a failed check. Modification time and provider checksums are diagnostic metadata; they never replace IRMind SHA-256.

`verify_graph` checks each generated Parquet artifact hash, its source linkage, and a reproducible rebuild. It never reads arbitrary Parquet or raw evidence chosen by a model. A canceled rebuild leaves the last verified version usable or fails closed.

Export v4 is a bounded-memory, length-prefixed streaming package containing the audit chain, signed source manifest and Parquet metadata, seal, and optionally the original bytes. `verify-export` validates the signatures and package structure without a keyring. When originals are omitted it reports **manifest verified; source bytes unavailable**, never **evidence verified**. Legacy v3 packages retain their existing verifier. Package paths are relative slash-separated names and cannot contain traversal or symlinks.

The proposed application result type distinguishes chain, manifest, source-byte, and derived-artifact verification. This requires extending the local export-verification port while preserving the existing v3 call for compatibility; the exact API must be reviewed before implementation.

## Benchmark storage

A [standard public GitHub Linux runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) has 14 GB of SSD, so a 15 GB raw corpus cannot be materialized alongside the build and Parquet output. The 15 GB benchmark will generate deterministic CloudTrail-shaped records directly into the streaming input during the job and discard each chunk after hashing and conversion. It measures the local pipeline, not object-store network latency or a physical source-disk read. A smaller 1 GB file corpus remains the check for local filesystem behavior.

## Guarantee change

An original copy makes offline re-verification and a portable evidence export possible. A manifest without that copy proves what IRMind observed and signed at ingestion time, but later byte verification depends on the original still being reachable and unchanged. A sampled check provides evidence only for the selected sources. Cloud object version identifiers improve repeatability but are not universal; without a stable version, verification compares the current object to the signed hash. No local signature alone proves that the analyst did not replace the entire chain with their own key.
