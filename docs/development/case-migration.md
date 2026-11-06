# Open-case migration to precise Parquet artifacts

This guide is for analysts and maintainers evaluating precise timestamps in an existing open case. Migration is optional. Existing V1 artifacts and sealed cases remain readable without migration.

## When migration helps

Migrate an open V1 case when the original logs contain subsecond timestamps or host-based queries would benefit from precise artifacts. Keep V1 when its current precision is sufficient; migration is not required to open, authenticate or export it. New ingestion uses V2 from either interface. Opening an existing case never migrates it.

## Before migration

Keep the original logs available. IRMind can use a retained original, a local source directory, or a verified local copy of a cloud object. It does not download cloud originals during this operation. Missing or changed originals stop migration. Keep enough free space for both generations and bounded private staging.

Open the case and run `/migrate --v2` for retained originals, or `/migrate --v2 <original-source-root>` for in-place sources. Review the confirmation. The task runs in the background and supports `/pause`. Migration requires the exact signed parser version. Retired parser versions are unavailable; create a new case and re-ingest verified originals with the current reader. Existing signed bytes still authenticate and export without rebuilding.

For automation, the equivalent is:

```sh
irmind migrate <CASE_ID> --artifact-v2 --source-root ./synthetic-originals
```

Omit `--source-root` when every original is retained locally. The command rejects sealed cases and unattended execution. It never changes a seal or deletes a historical artifact.

## What is checked

IRMind verifies the entire chain, every historical artifact and every required original before publishing replacements. It resolves the signed parser version and timestamp context. It reconstructs the old generation, compares record identity, content, entities, relations, counts and non-time query scope, and independently reconstructs the staged V2 files. A parser or scope change that alters record meaning stops migration.

Private staging is case-local and checked for available space. Replacement files are published under a generation directory derived from the old signed inventory. New artifact envelopes and one migration commitment enter the audit log atomically. Queries use the new set only after that complete commit. Failure or cancellation before commit removes owned replacement files; interrupted work is reconciled against the signed inventory on reopening. A completed commit remains completed if cancellation arrives afterward.

V2 can recover the precision present in the original. It cannot recover precision absent from that original. Historical files, signatures and source manifests stay intact.

## Verification and export

Run `/verify-graph <original-source-root>` to reconstruct both generations and compare their signed metadata and file hashes. Ordinary graph queries select only the committed active generation; explicit verification still checks historical artifacts.

Seal and export through the ordinary commands. Cases containing V2 artifacts or migration records use export V5 automatically. V5 carries both generations' signed metadata and hash-checked derived files, and can include originals. Public-key verification still accepts an expected analyst fingerprint and needs no keystore. V3 and V4 remain supported; a V4 package cannot carry V2 records.

New CLI, TUI and demo ingestion writes precise V2 artifacts. Opening a V1 case does not migrate existing artifacts or change its signed history. New sources can coexist with V1 sources; changing the artifact version of an already indexed source still requires explicit migration. CLI automation uses the same V2 writer and retains the explicit migration command. The [migration contract](parquet-v2-migration-contracts.md) describes the wire commitment and application boundary.
