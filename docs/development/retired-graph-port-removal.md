# Retiring unused buffered graph construction contracts

This contract records the final pre-1.0 source-pipeline cleanup. It removes interfaces whose implementations no longer construct or verify an index.

## Motivation

Every ingestion path uses `SourceDecoder`, an identified `SourceMapper`, `LargeCaseStore::prepare_mapped_ingest` and the signed V3 commit path. `LocalStore` rejects the old `EvidenceGraph` construction methods. No production caller invokes them. The `EventParser` object still travels through `EnginePorts` and local engine handles solely to satisfy those unused signatures.

## Removed contracts

Remove the `EventParser` trait, `EnginePorts::parser`, `Engine::parser` and the final parser argument of `EnginePorts::new`. Remove only these four methods from `EvidenceGraph`:

- `index_from_parser`
- `index_records`
- `rebuild_graph`
- `verify_graph`

Remove their rejected implementations, obsolete small-buffer parser implementations and corresponding unused fake methods. Keep the source decoder catalog, detection/time-context metadata, `SourceMapper`, current query methods and all `LargeCaseStore` verification methods. The TUI's case-level graph verification continues to use the signed Parquet verification use case.

`ModulePort::EventParser` currently identifies detector/selection metadata backed by `LogParser`; that separate module capability does not execute the removed trait and is unchanged here.

## Invariants and validation

No case, source, artifact, mapping, seal or export encoding changes. Current format golden bytes remain pinned. Ingestion, reconstruction and exported-package verification still authenticate sources, mapping profiles, receipts and physical artifacts. Policy, taint, ContentGuard, approval and resource limits remain unchanged.

Validation covers inward dependencies, native helper contracts, source/mapping contracts, signed worker determinism, all current format golden fixtures and the full release benchmark matrix. This is an API removal, not a new fallback or migration path.

## Projection coverage

The former buffered JSON implementation is removed. Its extraction assertions now
exercise `JsonSourceDecoder` and `JsonCompatibilityMapping` directly. Existing
current format golden fixtures remain unchanged. Decoder depth, framing, record
size, cancellation and provenance tests cover the active streaming path.
