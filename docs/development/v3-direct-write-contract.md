# Bounded direct mapped-artifact writing

This design is for evidence-store and ingestion maintainers. It describes writing final mapped Parquet files once, without creating signed intermediate Parquet parents during initial ingestion.

## Existing boundary

LargeCaseStore::prepare_local_batch returns one PreparedSource per original. LargeCaseUseCases signs each acquisition independently and requires each initial artifact to name that single source hash. This is correct for the existing implementation, but cannot retain a partition writer across many source files and atomically bind its final output to every contributing acquisition.

Keep that route unchanged for V1/V2. Do not join outputs by silently weakening the single-source check or assigning a multi-source artifact to the last file's manifest.

## Proposed additive local contract

Add an optional synchronous method to LargeCaseStore:

```rust
fn prepare_mapped_ingest(
    &self,
    request: MappedIngestRequest<'_>,
    cancel: &CancellationToken,
) -> Result<Option<Box<dyn PreparedMappedIngest>>, AppError> {
    Ok(None)
}
```

MappedIngestRequest carries the case, authenticated source root and ordered selections, copy policy, immutable decoder/mapping catalog and committed artifact metadata. It is never a network or credential port. The request can describe the complete ingestion, while workers open at most four sources at a time.

The opaque prepared result exposes acquisition manifests, source-record commitments and finalized unsigned physical outputs. Publish, retain-committed and Drop follow the existing migration/staging lifecycle. An application-owned assembler binds final SourceManifestV2 acquisitions, source sets, mapping snapshots, profiles, V3 outputs and mapping-run receipts before one atomic signed append per bounded group. No prepared storage object supplies signatures or authoritative audit entries.

Existing adapters default to None and keep their existing methods. The application selects the new path only for an explicitly enabled experimental V3 session. Missing implementation is an explicit unavailable error for a requested direct mapped source, not a silent downgrade. Unsupported source formats retain their declared historical route with visible coverage.

## Grouping without a format change

Preserve ParquetArtifactV3, MappingRunV1, ParquetLayoutV1, seal inventory V2 and export V6 field encodings. Preserve the 16 KiB V3 envelope, 128-source ceiling and 1 MiB metadata-frame ceiling.

Before writing a bounded source group, freeze its exact catalog and partition allocation. Hash and parse in canonical source order with bounded parallel workers. Finalize the original acquisitions and source commitments; create one profile for the group and bind every output to its actual contributors. Order source sets, bindings, outputs and receipts canonically. A group is committed completely or rolled back completely.

Size targets are upper targets, not permission to exceed a custody bound. Flush early when a further source binding would exceed the envelope or source-count ceiling. Flush only nonempty row groups. Such a file is already final and is not compacted automatically to hide that early flush.

Introduce a distinct physical recipe identifier, proposed as parquet-builder-common-event-direct-v1. It uses the existing builder-version field; it adds no envelope field or schema. Retain the current experimental builder for exact reconstruction where available. A verifier selects the recorded recipe rather than silently replaying a different file-cutting policy. The direct recipe and its physical golden bytes are tested independently; historical V1/V2 and their golden bytes are untouched.

## Bounded writers and stable order

Use final partition writers with bounded row-group and file targets, a global byte budget and a fixed maximum of active writers. Account for Arrow builders, unfinished row groups and retained footer metadata. Close a deterministic least-recently-used writer when the global budget requires it; no intermediate Parquet generation is later compacted as part of initial ingestion.

Chronological sources use the existing ordered replay. Disordered sources may retain private normalized runs and bounded merging; those are unsigned case-local staging, not Parquet parents. Feed the same shared stable comparator into the final writer. Cancellation is checked while hashing, decoding, merging and between bounded writes. Allocation, memory-pressure cuts and partition overflow must be deterministic, rather than depending on worker completion time or the machine's available RAM.

Free-space preflight includes final staged output, optional original copies and normalized-run estimates. Error, cancellation, failed signing and failed publication remove uncommitted files. Durable publication and the case lock preserve the previous signed generation across crashes. No evidence is written to the system temporary directory.

## Source failures and bounded retries

A source failure rolls back every provisional output and partition allocation of
its group. Retry the revised canonical source list once, omitting the identified
failed sources. A later, distinct source failure can repeat that process, with a
maximum of 16 excluded sources per group and a bounded final attempt. An already
excluded source is never retried. Reaching the bound fails the group with an
explicit count and reason.

Refill each group from the next canonical candidates after exclusions. Group
boundaries, partition allocation, filenames, source sets, profiles and output
commitments depend only on successful sources. Rejected candidates do not consume
source slots, partition cardinality or segment numbers. Thus ingesting 300 sources
with three corrupt files produces the same derived bytes and source/mapping
commitments as ingesting their 297 valid counterparts directly. The audit chains
intentionally differ because the first also records three rejections.

Use a closed source-failure classification: format, source limit, hash mismatch,
or source-specific cancellation. Record each rejected relative source, its fixed
reason and at most the existing bounded untrusted samples in the signed chain,
with no acquisition or Parquet artifact for that source. Use the existing generic
`ToolError` audit kind with a typed, canonical local-ingestion payload; this adds
no audit tag or custody frame format. Guard all displayed names and samples; no
rejected text reaches the model directly. Show accepted/rejected counts and each
source's reason in the TUI and automation results.

Disk, signing, publication, locking, catalog/configuration and unclassified errors
are operational failures. They roll back and fail without excluding sources or
retrying. Preserve previously committed groups. Record already identified source
rejections when the audit service is healthy; failure to sign or append is itself
terminal. A user cancellation aborts the complete operation, rolls back the
current group and is audited through the existing cancellation path. It never
becomes an automatic retry with a canceled parent token.

Preparation owns private provisional files until the application has validated
metadata, published and hash-verified files, and appended the complete group's
signed events atomically. Marking that group committed is infallible and performs
no I/O. Error or cancellation before the append removes all of that group's
uncommitted outputs; a later group cannot remove earlier committed outputs.

## Later small-file compaction

Initial ingestion does not call layout compaction. A later maintenance operation can use the unchanged compact_artifacts port and ParquetLayoutV1 only for a compatible partition whose small-file count exceeds a validated configured threshold. Evaluate count and size from the active signed inventory, not directory enumeration. The current operation retains parents; retirement remains separate future work.

## Required tests and measurements

- Many small originals in one partition produce final multi-source outputs and zero inactive parents.
- Mixed partitions, ordinary/overflow hosts and the 128-source/envelope boundaries preserve the complete record set and stable order.
- Repeated runs and different worker completion orders reproduce identical physical bytes and ordered commitments.
- Failure and cancellation at every preparation/publication/audit boundary leave no partial signed source group or orphan output.
- 300 synthetic JSON files with three late corruptions in distinct positions yield 297 accepted sources and three signed rejections. Compare every physical hash and source/mapping commitment with the clean 297-source ingestion, across refilled group boundaries.
- Source-limit, hash and source-cancellation fixtures exercise exclusions and the 16-source bound. Disk/signing/publication/lock failures prove zero exclusion retries. User cancellation stops the operation and cleans the current group.
- Exact source/mapping reconstruction and public-key-only V6 verification authenticate every final file.
- V2 default ingestion retains historical physical and canonical golden bytes.
- Compare before/after time, active disk, staging peak and inactive-parent bytes in the same release job for cloud and chronological/stress endpoint at 1, 64, 1,024 and 1,025 hosts.
- Keep every query, source/partition, custody and cancellation limit.

Default activation still requires the analyst's absolute and paired relative gates. Experimental format status does not authorize silently modifying V1/V2.
