# Layout-only derivations for mapped artifacts

This proposal is for evidence-store and verifier maintainers. It preserves the original decoding and mapping commitments when several mapped Parquet files are physically compacted.

**Status: accepted.** The source/mapping contracts remain those of [the approved design](source-mapping-design.md). This design adds a `ParquetLayoutV1` receipt and an explicit layout variant in the new V3 pipeline block. It changes no published V1/V2 envelope, seal-inventory V2 byte, physical common-event column or export V5 byte.

## Separate interpretation from physical layout

An ingestion mapping profile freezes one catalog and the complete accepted source-record sets. Its `MappingRunV1` receipt covers every resulting event and the complete mapped output inventory. These commitments remain immutable.

Physical compaction groups files by schema, partition and compatible mapping identity. A group can contain files from several ingestion profiles, or only one partition of a source that also produced other partitions. Compaction does not decode sources, select a new mapping or change any event.

Keep these two operations separate:

| Operation | Inputs | Signed result |
| --- | --- | --- |
| Decode and map | Authenticated originals, exact decoder, frozen mapping profile | Source sets, profile, complete mapped artifacts and `MappingRunV1`. |
| Compact layout | Authenticated existing V3 artifacts | New V3 layout artifact and `ParquetLayoutV1`. Original source sets, profiles and mapping runs remain unchanged. |

The deferred decoded-record cache and `RemapCommitV1` remain outside this proposal. Applying another mapping still requires a new case.

## Explicit bindings in V3

The unpublished V3 pipeline block has a closed derivation discriminator:

- `mapped`: the original profile reference, selected mapping or the explicit unclassified policy, and source-set references.
- `layout`: parent canonical-envelope identities, the exact original mapping bindings for each source, and a pinned layout-builder identity.

A layout binding contains the source hash, source-set reference, original profile reference, selected mapping identity and target-schema identity. Order bindings by source hash. Keep the existing limit of 128 sources per physical artifact. Two different bindings for the same source cannot be merged silently.

Only artifacts with the same physical schema, target, selected mapping identity, decoder contract, identity-normalization policy and compatible partition metadata can share a compacted file. A change to any of those properties requires another group. V1/V2 files are not converted through this operation.

The mapping identity is never put in `parser_version` or the physical builder field. A layout-builder identity describes only the deterministic row-merging and file-writing recipe. The source decoder and mapper identities retain their original meanings.

Derive a new relative output path from the ordered parent-envelope commitment, compatible binding metadata, schema, partition and output ordinal. Parent identities are known before writing the child. The complete child-envelope identity then authenticates that path and the file-byte SHA-256. Neither identifier depends on its own value or on the final receipt.

## ParquetLayoutV1

Add one explicit, versioned audit kind with its own canonical domain separator. Its bounded fields are:

| Field | Meaning |
| --- | --- |
| Layout contract and builder | Fixed versioned interpretation of a physical transformation. |
| Parent set | `u64` count and SHA-256 over ordered complete canonical V3 parent envelopes. |
| Replacement set | `u64` count and SHA-256 over ordered complete canonical V3 child envelopes. |
| Preserved bindings | Commitment to the exact source/mapping bindings carried from the parents. |
| Schema and partition | The one compatible family being reorganized. |
| Row count | Authenticated physical row count before and after compaction. |

Order each envelope set by relative path, rejecting duplicate paths and identities. Use separate domains for parents, replacements and binding commitments, with length-prefixed fields and fixed-endian counters. No commutative XOR accumulator is used.

Keep the existing `LargeCaseStore::compact_artifacts` signature: one call returns one replacement artifact. The application already has the parent manifests and can construct the receipt after verifying the returned artifact. A later multi-output layout operation would require its own reviewed contract.

The application appends the new artifact metadata and layout receipt in the existing atomic signed batch. Parents become inactive only after a complete, valid receipt. Keep their files and metadata for historical verification. Cancellation, a storage error or a failed audit transaction leaves the previously signed generation active.

The layout receipt is not a new mapping run. It makes no claim that the decoder or mapper executed again. Initial mapping coverage remains the responsibility of the original `MappingRunV1` receipts.

## Verification and export

Case verification checks the layout DAG without running downloaded mapping code:

1. Verify source sets, mapping snapshots, profiles and original mapping-run coverage as usual.
2. Require every layout parent to be an earlier authenticated artifact with a compatible schema and partition.
3. Recompute parent, replacement and binding commitments from signed entries. Do not accept supplied counts or commitments alone.
4. Require the replacement to preserve the complete parent binding set, row count and source hashes. Authenticate each referenced Parquet by its file SHA-256 before reading it.
5. Reject missing parents, cycles, incomplete replacements, duplicate activation, changed mapping identities and incompatible physical schemas.

Full `verify_graph` first reproduces the original mapped artifacts from the verified originals with their exact decoder, mapper and builder versions. It then replays layout operations in dependency order and compares each replacement's bytes. Local work stays cancelable between bounded batches, with private case-local temporary files removed on completion or error.

Export V6 includes all necessary parent and child artifact envelopes and files, mapping snapshots, source sets, profiles, original mapping receipts and layout receipts. Its bounded range reader checks hashes and physical schemas without extracting a Parquet to the system temporary directory.

Signature/file authentication is reported separately from full source and transformation reconstruction. An offline exported package can be authenticated without executing a native mapper or contacting a service. That does not establish that original source decoding and every layout operation were reproduced.

Seal-inventory V2 keeps its existing encoding. Coverage includes the complete canonical V3 envelopes for retained parent and child files; the signed chain head also binds the layout receipt. Verifiers recalculate inventory counts and hashes from the chain.

## Bounds and tests

The metadata frame limit remains 1 MiB. Parent/source collections retain their existing bounds. New V3 metadata has an explicit bounded codec; historical envelope limits do not change.

Shared contracts must cover:

- Two sources with different original profiles but the same immutable mapping identity.
- One source producing several date/host partitions, with only one physical group compacted.
- Same Parquet bytes under different derivation envelopes.
- Changed or omitted bindings, parents, rows, schemas and replacement files.
- Cancellation and audit rollback before replacement activation.
- Public-key-only export V6 authentication and exact full reconstruction.
- New layout/envelope goldens alongside unchanged historical goldens and seal challenges.

Repeat the release benchmark matrix with compaction enabled for both sides: three representative 1 GiB repetitions and the complete 15 GB cloud/endpoint matrix. Keep the existing time, query, sample, hop, expansion and token gates. Measure layout time and retained/staging disk use separately from decoding and mapping.

For every 15 GB scenario, report inactive-parent bytes separately, their percentage of total retained case bytes, and their ratio to active-artifact bytes. If retained parents exceed approximately 20% of active-artifact bytes, prepare a separate design for an analyst-signed retirement operation; do not implement it in this change. That design must preserve envelopes and receipts, explain which original files are needed for regeneration, and distinguish the loss of direct file authentication from full reconstruction that regenerates the missing parents.

## Alternative

An implementation can initially omit V3 compaction while retaining the historical V1/V2 paths. Its benchmarks must retain all mapped records, report the additional files and query cost, and keep the writer opt-in whenever the existing gates fail. It must not label a partial physical group as a complete source-mapping run.
