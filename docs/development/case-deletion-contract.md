# Signed deletion of open cases

Proposed application/storage contract for analyst-driven logical deletion. No
deletion is performed by this document. Sealed cases remain undeletable. Current
case, export, seal and global-operation canonical bytes are unchanged.

## Ownership and durable intent

The local adapter has a shared SQLite database, content-addressed evidence blobs,
and per-case Parquet trees. It must not treat the entire data directory as owned
by one case. External originals, installed methods, configuration, the global
journal and other cases are never deletion targets.

The Analyst first reviews the title, creation time, source count and storage
measurement and types the exact title or case ID. An optional reason is bounded
to 1,024 UTF-8 bytes. The application verifies the case and global chains under
the deletion lease, rejects any seal/file/pending seal, and creates one
`case-deleted-v1:` global operation. Its suffix is hex of the canonical receipt
below. The existing Analyst `SignedOperation` envelope authenticates it. No model
or child tool exposes this application operation.

The storage adapter commits that signed operation and a deletion-intent row in
**one SQLite transaction**. The intent immediately excludes the case from normal
listing/opening, before any file is removed. A failed signature or failed intent
transaction leaves the case unchanged. File removal and deletion of case-local
rows are idempotent work authorized by that immutable receipt. They finish before
the adapter marks cleanup complete. The signed tombstone remains in the global
journal forever; completion/error progress is operational state, not new custody.

On startup, the engine authenticates the global journal using its trusted Analyst
verifier before passing validated receipts to recovery. A failed cleanup remains
a visible tombstone with an actionable retry/error, never a valid open case.
Recovery neither generates a new signature nor trusts a database marker alone.

Existing append-only protections remain for normal operations. Their deletion
exception is limited to the target of an authenticated, committed intent and an
unsealed case; global operations still cannot be changed or deleted. Schema tests
must keep all case-owned tables covered. No general-purpose delete API or SQL
escape hatch is introduced.

## Proposed ports

A separate optional `CaseLifecycleStore` avoids changing existing repository,
audit, export or ingestion method signatures. The engine receives it through an
additive `with_case_lifecycle(Arc<dyn CaseLifecycleStore>)` composition method.
Existing adapters without this port cannot delete cases.

```rust
pub trait CaseLifecycleStore: Send + Sync {
    fn open_session(&self, id: &CaseId) -> Result<Box<dyn CaseLock>, AppError>;
    fn prepare_deletion(
        &self, id: &CaseId, cancel: &CancellationToken,
    ) -> Result<Box<dyn PreparedCaseDeletion + '_>, AppError>;
    fn resume_deletion(
        &self, deletion: &VerifiedCaseDeletion, cancel: &CancellationToken,
    ) -> Result<DeletionProgress, AppError>;
}

pub trait PreparedCaseDeletion: Send {
    fn inventory(&self) -> &CaseDeletionInventory;
    fn commit(
        self: Box<Self>, operation: &SignedOperation,
    ) -> Result<DeletionProgress, AppError>;
}
```

`VerifiedCaseDeletion` has private construction in the application; adapters get
read-only accessors after full global-chain authentication. `CaseDeletionInventory`
contains immutable case/storage measurements, not arbitrary deletion paths.
`DeletionProgress` distinguishes completed cleanup from pending cleanup and an
explicit error. Unsupported storage returns an error, never a no-op success.

The application preview owns the prepared lease through confirmation. Cancel or
Esc drops it without signing. Commit rechecks the receipt against the prepared
case and storage inventory, including its tail/count, before the transaction.
An internal helper builds the existing signed-global-operation envelope without
appending first; the adapter commits it with the intent. Existing global appends
reuse the same canonical/signature code and retain their existing bytes.

## Open sessions, locking and process safety

Current case locks protect individual operations, not the complete open TUI
session. A lifetime shared session lease therefore uses the existing private lock
directory and `fs4` implementation. Deletion requires its **nonblocking exclusive**
counterpart and the existing exclusive case-operation lock. It fails clearly if
another session or operation holds either; it does not wait indefinitely.

Every interactive case session holds the shared lease until it closes. A delete
command from that session cancels/joins its background work and returns to the
home controller before taking the exclusive deletion lease. A sealed case is
rejected without closing it. Existing CLI operation locks continue to exclude
concurrent mutation; interactive CLI sessions hold the same lifetime lease.

The order is session lease, case-operation lease, global evidence-maintenance
lease when needed, global journal lease, SQLite transaction. Recovery follows the
same order. Lock files stay as coordination objects; unlinking a live lock file
could let another process lock a different inode.

## Files, shared blobs and storage measurements

Only adapter-derived paths for the validated UUID are traversed: the per-case
Parquet tree (including originals, spool, staging, proofs and method snapshots),
case branch/journal files if any, and its seal path, which must be absent for an
eligible case. No source URI or original relative path is used as a deletion path.
Traversal is bounded and does not follow symlinks, junctions or reparse points.
An unexpected link or inaccessible entry stops cleanup and leaves a pending
receipt; it never broadens the deletion root.

Shared evidence blobs are reclaimed only when no other case references them.
Evidence publication and deletion share a maintenance lock across reference checks
and file effects, so publication cannot race garbage collection. The target's
reference removal and pending-work manifest are committed atomically. Recovery
rechecks surviving references under that lock. Blobs needed by another case stay.

The preview and receipt distinguish:

- `owned_file_bytes`: exact sizes of case-private files at preparation;
- `shared_blob_bytes`: logical bytes referenced by this case in the shared pool;
- `logical_metadata_bytes`: bounded SQLite payload accounting, not allocated pages.

The UI labels the shared/metadata contribution explicitly. It does not promise
that SQLite shrinks or that shared bytes are freed. The immutable receipt records
the authorized inventory, not a false measurement of reclaimed physical space.
Cleanup progress can report actually unlinked bytes separately. Concurrent shared
references can reduce reclaimable space without changing the target's case data.

This is logical deletion, not secure erasure. SSD wear levelling, snapshots,
backups, WAL and free pages may retain data. Recommend full-disk encryption for
sensitive evidence; never claim forensic data sanitization.

## Receipt and vectors

`CaseDeletedV1` uses fixed-order struct JSON with these fields:
`version`, `case_id`, `title`, `created_at`, `last_chain_hash`, `entry_count`,
`source_count`, `owned_file_bytes`, `shared_blob_bytes`, `logical_metadata_bytes`,
`reason`, `deleted_at`. Counters/times are bounded u64; version is 1; the case ID is
validated; the tail is 64 lowercase hex characters; title is at most 200 UTF-8
bytes; reason is absent or at most 1,024 bytes. No floats or unordered JSON maps.
The receipt's deletion time equals the envelope timestamp. At least one entry
must exist, sources cannot exceed entries, and receipt validation includes the
case creation record and the complete verified tail/count.

[receipt.json](case-deletion-vectors/receipt.json), its
[SHA-256](case-deletion-vectors/receipt.sha256) and
[hex](case-deletion-vectors/receipt.hex) fix the proposed payload bytes.
`case-deleted-v1:` plus that hex is the operation text. The current global envelope
is reused; no existing vector is rewritten.

## Acceptance checks

- Unsigned/mismatched receipts, signing failure, cancellation before commit and
  sealed/pending-seal cases remove nothing.
- Two native processes prove that an open session blocks deletion and that a
  running mutation cannot overlap it, including Windows lock behavior.
- Interrupt after intent, during file cleanup and before final metadata removal;
  reopening authenticates and resumes, or reports the pending tombstone.
- Repeated recovery is idempotent; no deleted case reappears as an open case.
- Original files outside the data root and another case's shared evidence remain
  byte-identical. A shared publication race cannot remove a newly used blob.
- Symlinks/junctions, unexpected roots and invalid UUIDs cannot cause traversal
  outside case-owned storage.
- Tombstone title/reason are guarded and terminal-escaped on display and never
  enter model system messages. An obedient fake model and child cannot invoke
  deletion, invent confirmation or obtain the Analyst signature.
- Golden receipt bytes are checked with insertion-ordered JSON enabled too.
