# Source query capture publication

The approved [source-query contract](source-queries-format-contract.md) uses a
case-owned capture at `queries/<sha256>.sqc`. A query capture is a portable
derived original. Export V9 carries it in the mandatory capture section and
never duplicates it among optional file originals.

The current `LargeCaseStore::prepare_mapped_ingest` copies evidence to
`originals/<sha256>`. Its preparation owns both the copy and the derived files
until the signed append succeeds. `create_object_spool` creates an auto-removed
private temporary file. Neither method owns a committed copy in the separate
query namespace or opens that copy for verification. Ordinary file sources may
have any validated relative path, including `queries/`; that prefix cannot
grant derived-source identity.

## Additive storage methods

Add two optional methods to `LargeCaseStore`. The default implementation of
each returns an unavailable error before any I/O.

```rust
fn prepare_source_query_capture(
    &self,
    request: &MappedIngestRequest<'_>,
    capture: &SourceQueryResultV1,
    cancel: &CancellationToken,
) -> Result<Box<dyn PreparedMappedIngest>, AppError>;

fn open_source_query_capture(
    &self,
    case: &CaseId,
    hash: &EvidenceHash,
    bytes: u64,
    cancel: &CancellationToken,
) -> Result<Box<dyn std::io::Read + Send>, AppError>;
```

Preparation accepts exactly one case-local spool and verifies its length and
capture digest against the result. The capture descriptor and page commitments
must also match. The adapter derives the installed path from the validated
digest. The mapping uses the signed result's decoder and pinned mapping.
Source provenance is ToolResult, and offsets refer to the retained capture.
The existing prepared group publishes the capture in the query namespace
together with mapped artifacts. It returns the usual metadata and supports
rollback and retention through the existing `PreparedMappedIngest` interface.

The existing case lock covers publication. The app appends the signed result,
derived manifest, mapping and Parquet receipts, and retention settlement as one
batch. The earlier reservation, submit intent and execution records survive
rollback. An interruption can leave an unreferenced private file; open-time
cleanup checks the authenticated case inventory before removing it.
Signed references to missing, changed or duplicated captures fail verification.

Verification opens the digest-derived regular file without following links.
It checks length on the same handle and streams it through the capture verifier.
The caller supplies an identity already authenticated by the principal chain.
The exporter writes exactly that inventory in digest order and retains the
mandatory V9 capture counter. Paths, extra fields and common frame limits remain
as defined in the approved format.

## Tests

- Verify a committed capture and export it without the original source directory.
- Drop a failed preparation or fail the audit append and verify that neither
  capture nor artifacts become evidence. The prior usage and reservation remain.
- Reject wrong case, digest, size, decoder, page commitment, symbolic and hard
  links, duplicate frames, a substituted file source and changed capture bytes.
- Reconcile interrupted publication from signed inventory and preserve the
  committed capture on reopen. Cancel before and during file verification.
