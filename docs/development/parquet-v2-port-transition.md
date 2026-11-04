# Approved ports for mixed artifact ingestion

This document records the analyst-approved application contracts for artifact-V2 step (b). The [approved design](parquet-artifact-v2-design.md#parser-transition) calls for additive typed parser metadata and review of the exact port changes before implementation. [Step (a)](https://github.com/ns2switch/irmind/pull/167) defines the checked time and envelope. The analyst approved the versioned storage boundary and both additive parser callbacks before their implementation in [PR #168](https://github.com/ns2switch/irmind/pull/168). The historical signed formats and dependencies stay unchanged.

## Why an application contract needs to change

`PreparedSource.artifacts` and the `LargeCaseStore` artifact operations currently accept only `ParquetArtifactV1`. Passing V2 through those fields would require hiding it in a V1 schema/parser string, which the approved design forbids. The streaming callback also carries only `GraphRecord`; it cannot explicitly express source precision, inference or an optional byte offset without changing that existing struct.

## Storage boundary: one versioned value

Introduce a domain sum type with two explicit variants:

```rust
pub enum ParquetArtifact {
    V1(ParquetArtifactV1),
    V2(ParquetArtifactV2),
}
```

Its accessors expose the common path, hash, source hashes and parser identity. Encoding dispatches to the existing exact V1 or new V2 codec; it never rewrites V1 as V2. The signed audit kind selects the variant. An unknown kind/schema fails closed.

Use this value at these existing `LargeCaseStore` boundaries:

| Boundary | Existing | Proposed |
| --- | --- | --- |
| `PreparedSource.artifacts` | `Vec<ParquetArtifactV1>` | `Vec<ParquetArtifact>` |
| `prepare_legacy_evidence` result | `Vec<ParquetArtifactV1>` | `Vec<ParquetArtifact>` (the legacy path still produces V1) |
| `compact_artifacts` input/result | V1 slice / V1 | versioned slice / versioned artifact; compatible versions only |
| `verify_artifact` input | V1 reference | versioned reference with exact schema dispatch |
| `rebuild_compare` artifact input | V1 slice | versioned slice with pinned parser resolution |

Other arguments, synchronous execution, cancellation, case locking and private spool ownership stay unchanged. This is a Rust API change for adapter implementations, not a rewrite of signed data. It keeps one ingestion/signing/verification path. The alternative is a second set of V2-only storage methods; that would duplicate the custody pipeline and require every caller to choose a version-specific path. The versioned value is recommended.

The internal signed-manifest index holds both variants. Every artifact is verified by hash before use; V2 source/supersession links and schema identifiers are checked explicitly. V1 reconstruction continues to use its historical parser and bytes. No remote execution or approval port changes.

## Parser boundary: additive callbacks

Keep `GraphRecord` and every current method unchanged. Add a separate value:

```rust
pub struct IndexedGraphRecord {
    pub record: GraphRecord,
    pub time: Option<IndexedTime>,
    pub source_offset: Option<u64>,
}
```

Add `parse_indexed_reader_report` and `parse_indexed_local_file_report` to `StreamingEventParser`. Their source, reader/file, evidence hash, cancellation and `ParseReport` arguments match the existing report methods; only the callback receives `Tainted<IndexedGraphRecord>`. Default implementations preserve existing parse output and provenance, use no invented offset and label legacy second-resolution output as coarse. Missing time stays absent. Existing adapters and fakes compile without implementing the optional methods.

Precise native implementations must read the full source timestamp, declare its actual precision/inference, and retain its original representation. A parser must not advertise a precise V2 capability merely because the default adapter can lift its old coarse output. Parser identities/capabilities and each version change will be explicit in the implementation and reconstruction tests. Historical versions do not acquire new behavior. Byte offsets must be consistent per source; grouped events or CSV rows with embedded newlines use record identity unless a real byte offset is known.

The local-file method remains separate so OCSF Parquet retains random access without a system-temp copy. Remote input continues through the approved private case spool. Parsed values remain tainted with source/parser/offset provenance; no raw content enters a system message.

## Verification and rollout evidence

- Existing parser normalized-output and signed V1 goldens remain identical, with both JSON map-order configurations.
- Default parser methods preserve output and taint; precise overrides test fractional epochs, explicit offsets, inferred time, null time and real/absent source offsets.
- One comparator orders all time-bearing query results by instant, signed source identity and consistent byte-offset/record identity. V1 remains visibly coarse.
- Mixed cases verify all artifacts and source links before querying; unknown identifiers, inconsistent row times, parser mismatch and partial replacements fail closed.
- Compaction never drops precision or quietly merges incompatible parser/schema/partition policies. Cancellation and failure leave the old committed set active.
- The mixed reader/writer does not silently export a V2 case as V4. Export V5 and explicit open-case migration remain their separate approved step (d).

No production dependency, credential, policy ceiling, query budget or signed-source encoding is added or relaxed by this proposal. The storage API generalization and both additive parser methods have analyst approval.

## Step (b) implementation and rollout

The mixed reader validates the signed parser binding, builder, physical schema, source hashes and each selected artifact hash before returning rows. Numeric inclusive time filters compare microseconds plus residual nanoseconds. Search, timelines, entity extrema and path citations share one domain comparator. V1-only display stays unchanged; mixed results label coarse or inferred time. A single source cannot mix byte-offset and record-number ordering.

Native indexed callbacks preserve the exact existing `GraphRecord` and provenance. They recover fractions from the original normalized record rather than its V1 display timestamp. Source format determines precision, including explicit zero fractions. The new builder version pins this additional derived behavior; historical reconstruction calls the unchanged legacy callbacks. A precision failure counts as a rejected record, while a storage or cancellation error still aborts. The default callback labels legacy output as second precision and never invents offsets.

`ParquetStore::open_precise` and `LocalStore::open_precise` explicitly construct the V2 writer for integration and golden tests. This intermediate step writes UTC-date-only V2 partitions and keeps actual account/region/host columns for exact row filtering. Generic scope allocation is the separate approved step (c). Default CLI/TUI composition remains V1 until that allocator and export V5 are available, preventing an intermediate build from creating ordinary cases it cannot export. V1 and V2 have separate paths, codecs and compaction groups. Mixed compaction is rejected rather than dropping precision. No signed file is rewritten or deleted.

Explicit migration and V5 export remain step (d). V3/V4 verifiers continue rejecting V2 events, and new V2 supersession links remain unavailable until the atomic migration validator exists. The case seal format stays unchanged; its V2-aware manifest/recovery and export tests belong to step (d). This staging does not expose a second production ingestion dispatcher or a default LLM.
