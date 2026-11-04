# Proposed ports for mixed artifact ingestion

This proposal is for the analyst reviewing the exact application contracts for artifact-V2 step (b). The [approved design](parquet-artifact-v2-design.md#parser-transition) calls for additive typed parser metadata and review of the exact port changes before implementation. [Step (a)](https://github.com/ns2switch/irmind/pull/167) defines the checked time and envelope. This PR contains a proposal only; it does not change code, signed formats or dependencies.

## Why an application contract needs to change

`PreparedSource.artifacts` and the `LargeCaseStore` artifact operations currently accept only `ParquetArtifactV1`. Passing V2 through those fields would require hiding it in a V1 schema/parser string, which the approved design forbids. The streaming callback also carries only `GraphRecord`; it cannot explicitly express source precision, inference or an optional byte offset without changing that existing struct.

## Proposed storage boundary: one versioned value

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

## Proposed parser boundary: additive callbacks

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

No production dependency, credential, policy ceiling, query budget or signed-source encoding is added or relaxed by this proposal. Review is needed for the storage API generalization and the exact additive parser methods before their implementation.
