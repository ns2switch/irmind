# Typed common-event core

This page is for parser and evidence-store maintainers. It describes the first implementation layer of the [common-event design](common-event-schema.md). Source-specific interpretation is separate work.

## Validated boundary

`irmind-domain` owns the closed category, type, outcome, kind, role and field codes. The [frozen code table](../../crates/domain/src/common_event/goldens/codes-v1.tsv) fixes their wire values. `CommonEventV1` has private fields, checked constructors and a 64 KiB projection limit. IPs, ports, PIDs, hashes, timestamps and identity scopes have representation checks. Errors do not echo evidence values; content-bearing debug output is redacted.

The context uses a closed `CommonField` map with checked `CommonValue` variants rather than arbitrary JSON paths. This provides sparse optional groups without exposing unvalidated field assignments. It preserves the field meanings in the design. Unknown source attributes remain in the bounded original record.

The application pairs the projection with the existing indexed record and its tainted provenance. Before staging, it corroborates the source hash, record index, real offset, parser identity and timestamp. An opaque checked view ties the canonical encoding to an immutable event borrow. The writer reuses those checked bytes instead of serializing the same event twice; provenance, time and size checks remain in place. Canonical JSON orders every object recursively and uses checked integer timestamps. Enabling `serde_json/preserve_order` cannot change it.

New ingestion follows the [source/mapping boundary](source-mapping-design.md): a registered `SourceDecoder` emits bounded `Tainted<SourceRecordV1>` values from original fields; a frozen `MappingCatalog` selects a pure `SourceMapper`; the writer validates origin, time, projection and role-bearing observations. The native modules have nondefault `mapping-json-compat` and `mapping-journald-compat` composition features; registering them does not activate the writer. No `parse_common_*` method or normalization bridge remains in `StreamingEventParser`.

`mapping-json-compat` and `mapping-journald-compat` are independent extraction-only native modules. Their recursive historical projections cannot be expressed by finite tables. Their identities include content-addressed source/build manifests. They preserve role-free search identities without inventing classifications. The new [table interpreter](mapping-tables.md) supports bounded declarative mappings and shares the same contracts. Missing mappings produce an explicit unclassified event. Parsers without a registered raw decoder retain their unchanged historical route.

## Physical schemas and reconstruction

Historical V1/V2 envelopes and export V5 remain unchanged. New mapped artifacts use `ParquetArtifactV3`, authenticated profiles and receipts, and export V6. New schema identifiers and the new builder `parquet-builder-common-event-v1` select the typed layout:

| Schema | Additional columns |
| --- | --- |
| `irmind-events-v4` | Category/type bitsets (`UInt32`), outcome/kind (`UInt8`), canonical common payload, observation-role membership (`UInt16`). |
| `irmind-entities-v4` | The same classification columns; role (`UInt8`), field code (`UInt16`) and canonical identity scope. |
| `irmind-coobservations-v3` | The entity columns plus scoped role/field peer descriptors. |

The event role mask supports filtering an event by a reported occurrence without an unbounded join. The legacy entity-pair projection remains available; it does not replace role-bearing observations. Roles label occurrences, not extra global nodes or directed attack edges.

`co_observations` stores typed descriptors only. Role-free pairs remain in `co_entities`; the reader combines them while suppressing an unspecified duplicate of an explicitly typed `(kind, value)` key. It also accepts complete descriptor lists. Invalid descriptors fail validation before any legacy merge. Same-value roles, scoped identities and PID lifetimes keep their original meanings. See the [peer-layout design](common-event-peer-layout.md).

Unknown codes, incompatible column types and schema/builder metadata mismatches fail validation. New envelope and payload goldens supplement historical fixtures; historical bytes are unchanged. Hash verification still precedes each Parquet read. Compaction and consolidation retain the validated common-schema file metadata; record batches alone do not carry that file metadata. Reconstruction chooses the builder recorded in the signed artifact and reproduces the complete artifact set.

V6 verification checks the common physical columns and file metadata after authenticating each derived frame's complete hash. A bounded file-range reader exposes only that frame to the Parquet reader; it neither extracts evidence to temporary storage nor reads neighboring frames. The direct `bytes` dependency supplies the return type required by Parquet's `ChunkReader` interface. The package is already present in the lockfile; no new package or feature is introduced.

Old store constructors keep their historical writers. `open_mapped` explicitly selects the new decoder/mapping writer for supported sources in new batched ingestion. Merely opening a case does not reparse its sources or change its generation.

The unsigned normalized spool stores each observation vector once. Deserialization recreates its JSON cache before memory accounting or batch construction; final schemas, batch inputs and golden bytes remain unchanged. The writer also reuses already sorted legacy entity pairs. These changes do not implement co-observation by reference or the separate bounded-metadata proposal.

## Queries and coverage

Existing tools accept optional `event_category`, `event_type`, `event_outcome` and `entity_role` selectors. Values come from closed enums; selectors combine with AND. CLI flags use hyphens; TUI graph commands accept `--event-category=authentication --event-outcome=failure`. Time, host and organization ceilings remain independent constraints.

Unclassified or historical records cannot match a classification or role they do not have. Filtered results explain incomplete schema coverage. A graph summary reports common, categorized and known-outcome counts. Absence of classified matches is not proof that the activity did not occur.

Entity lookup separates identity scopes and reports per-role observation counts. A PID without a lifetime identifier is source/record scoped; its reuse cannot bridge unrelated events. Same-value source and destination occurrences remain distinguishable, while event timelines deduplicate the source/record reference. Neighbor/path searches retain the existing 4,096-record sample, 3-hop, 200-expansion, 50-neighbor and 10-second budgets. Historical entity-only artifacts retain a bounded fallback.

A retained homogeneous scope/role/field batch computes timestamp extrema once and combines that group's extrema into the total. Mixed batches and scopes beyond the 20-detail cap retain the general path. Counts, precision markers, invalid-code rejection and the scope-detail limit are unchanged.

## Compatibility boundary

No semantic migration is implemented. `CommonEventMigrationV1` is deferred. V1/V2 cases remain readable without migration; new semantic interpretation requires re-ingestion into a new case. The existing precision-only migration cannot activate a common-schema replacement.

Source-specific semantic mappings and the Elastic/Chronicle connectors follow the core separately. A source alert never becomes a confirmed report finding automatically. Model-facing and terminal-facing projections still pass through the existing guard and redaction paths.

## Validation and measurement

Tests cover the codebook, canonical payload/envelope goldens, invalid typed values, same-value roles, PID reuse, unmapped records, mixed readers, custody, public-key-only V6 verification and deterministic reconstruction. The shared decoder/mapping contract checks deterministic repeated and parallel projection, taint and cancellation. The preserve-order job runs common goldens and table-interpreter contracts.

Format tests exercise every closed context-field type and all identity-scope encodings in both JSON map modes. The latest [mapped-pipeline AddressSanitizer runs](benchmarks/mapped-pipeline-fuzz.json) record the exact source revision and 600 seconds per target: 5,542,630 canonical-codec executions, 3,140,406 export-verifier executions and 8,427,493 declarative-table executions, without a crash. Earlier [physical-core](benchmarks/common-event-core-fuzz.json) and [range-reader](benchmarks/common-event-export-fuzz.json) runs remain separately identified.

The manual graph benchmark supports a paired common-schema run against a pinned baseline: three smoke repetitions for representative cloud and endpoint sources, then one 15 GB pass per cloud/endpoint scenario on the same runner class. Builds use release optimization. The existing ingestion/query gates are unchanged. HuntEval has 18 episodes and 13 distinct public source hashes. Both paired variants ingest those unique source bytes once and evaluate all 18 episodes, keeping private answers evaluator-only. The baseline receives only the identical test-harness staging rule and the 1 GiB smoke wrapper; its production code is unchanged. The mapped benchmark uses the real extraction-only cloud and journald modules; it never substitutes an empty graph. It measures decoder, pure mapping, checked projection, input commitment, Parquet, compaction and custody costs separately. It does not claim semantic coverage of future source-specific mappings.

The [initial physical prototype](benchmarks.md#common-schema-core-initial-iteration) and [sparse peer matrix](benchmarks.md#common-schema-core-sparse-peer-matrix) remain historical measurements. The latest [decoder/mapping/layout matrix](benchmarks.md#source-decoding-mapped-v3-and-retained-layout-parents) measures all nine release pairs and both three-repetition 1 GiB smokes through the real source pipeline. It still misses ingestion and dense entity-query gates, so the common writer remains opt-in. Normal CLI/TUI/demo writing stays on the existing V2 builder.

## Signed derivations and retained layout parents

`SourceRecordSetV1` binds the complete final source manifest, exact decoder and temporal context, rejected count and ordered source-record commitment. `MappingProfileV1` freezes input-set references and immutable mapping snapshots without a circular output reference. A complete `MappingRunV1` activates its complete output inventory atomically. A source SHA-256 has one mapped generation per case; retrying the same recorded path verifies and reuses that acquisition; another acquisition of the same bytes under a different path is rejected before adding custody entries. Reuse the existing evidence or ingest into a new case. This does not change the published historical route.

Physical compaction uses the [approved layout receipt](mapped-artifact-layout.md). A V3 `layout` artifact preserves every original binding and names earlier compatible parents. The application signs the replacement and `ParquetLayoutV1` together. Parent files and the original profiles/receipts remain retained. Authentication checks the complete graph and every file hash; full reconstruction reruns exact locally available implementations and then replays physical layouts.

Export V6 adds an ordered list of the analyst-signed global operations needed to authenticate installed mapping definitions, after case operational entries and before artifact frames. A count and bounded frame encode each proof. No unrelated global configuration or credentials are exported. The verifier requires exactly the referenced proofs, validates their analyst key and contents without executing a mapping, then checks every retained parent/child file. V1/V2, seal-inventory V2 and export V5 golden bytes are unchanged.
