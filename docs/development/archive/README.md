# Development archive

These pages record earlier contracts and implementation decisions. Use the [architecture](../architecture.md) and [case format guidance](../../cases.md) for the current version.

| Document | Status |
| --- | --- |
| [Case migration](case-migration.md) | Superseded by the [current case format guidance](../../cases.md#cases-and-exports-from-an-earlier-version). This page records the v0.5 transition. |
| [Json format order](json-format-order.md) | Historical transition. Current parsers retain canonical JSON ordering and alternate-feature CI coverage. The legacy parser identities described here have been retired. |
| [Json line order compatibility](json-line-order-compatibility.md) | Historical release audit for v0.1.0–v0.1.5. The legacy parser identities and the compatibility paths described here have been retired. |
| [Parquet artifact v2 design](parquet-artifact-v2-design.md) | Implemented for v0.2 and superseded by [mapped V3 artifacts](../source-mapping-design.md). Current cases have no standalone V1 or V2 reader or precision migration command. |
| [Parquet artifact v2 wire](parquet-artifact-v2-wire.md) | Implemented for v0.2. The standalone envelope was superseded by mapped V3; this document records the old wire contract. |
| [Parquet v2 migration contracts](parquet-v2-migration-contracts.md) | Implemented for v0.2. The V1/V2 migration path and export V5 were retired under the [pre-1.0 format policy](../decisions.md#pre-10-format-policy). |
| [Parquet v2 partition contracts](parquet-v2-partition-contracts.md) | Implemented for v0.2. The current mapped writer retains bounded scope partitioning. The V2 rollout contracts are historical. |
| [Parquet v2 partition replay](parquet-v2-partition-replay.md) | Implemented for v0.2. Current mapped artifacts retain source-bound partition validation; the standalone V2 replay path is historical. |
| [Parquet v2 port transition](parquet-v2-port-transition.md) | Implemented for v0.2 and superseded by the [separate source decoder and mapping pipeline](../source-mapping-design.md). The mixed V1/V2 writers and readers have been retired. |
| [Retired graph port removal](retired-graph-port-removal.md) | Implemented for v0.3. The retired graph ports were removed; see the [current architecture](../architecture.md). |
| [V1 to V2 precise-time migration](v2-precision-migration.md) | Retired analyst procedure for v0.2. |
| [Early large-case custody format](parquet-custody-design.md) | V1 artifacts and V3/V4 exports, superseded by the mapped pipeline. |
| [Sigma and reports in V10](../sigma-report-v10-wire.md) | Historical case 6 header, V10 archive and Sigma run V1. The case 7 contract supersedes them. |
| [Sigma source classes](../sigma-source-class-compilation-contract.md) and [interactive Azure projection](../sigma-azure-result-type-contract.md) | Historical evaluator identities. The V3 result format, source classes and approved projections remain active in V5. |
| [V4 Sigma package admission](../sigma-package-v4-admission.md) | Historical evaluator suffix. Case 7 represents admission in a distinct receipt field. |
| [Original Sigma and report proof review](../sigma-report-proof-objects.md) | Historical V1 result and coverage examples. Current object encodings are covered by the case 7 contract. |
| [V9 source-query contract](../source-queries-format-contract.md) | Historical archive framing. V11 retains the approved source-query receipts and captures. |
