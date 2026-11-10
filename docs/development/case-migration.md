# Cases from an earlier version

This guide helps analysts keep a verifiable record when a pre-1.0 case or export uses a retired format.

The current writer uses mapped V3 Parquet artifacts and export V6. Opening a case does not migrate or rewrite it. A retired case or export format is rejected before reconstruction or export.

1. Keep the IRMind version that created the case. Use it to open and verify the original chain and to export any record you need to retain.
2. Verify the original sources against that case's signed manifests. Preserve its original case and any sealed package separately.
3. Create a new case and ingest the verified originals with the current version. This produces a new signed chain. It does not carry forward analyst approvals, confirmed findings or seals from the earlier case.
4. Check the resulting sources, mappings and artifacts with the current verification commands.

Historical V1 to V2 procedures are retained in the [development archive](archive/v2-precision-migration.md) for users of the versions that supported them.
