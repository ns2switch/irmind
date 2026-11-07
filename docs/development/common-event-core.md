# Typed common-event core

This page is for parser and evidence-store maintainers. It describes the first implementation layer of the [common-event design](common-event-schema.md). Source-specific interpretation is separate work.

## Validated boundary

`irmind-domain` owns the closed category, type, outcome, kind, role and field codes. The [frozen code table](../../crates/domain/src/common_event/goldens/codes-v1.tsv) fixes their wire values. `CommonEventV1` has private fields, checked constructors and a 64 KiB projection limit. IPs, ports, PIDs, hashes, timestamps and identity scopes have representation checks. Errors do not echo evidence values; content-bearing debug output is redacted.

The context uses a closed `CommonField` map with checked `CommonValue` variants rather than arbitrary JSON paths. This provides sparse optional groups without exposing unvalidated field assignments. It preserves the field meanings in the design. Unknown source attributes remain in the bounded original record.

The application pairs the projection with the existing indexed record and its tainted provenance. Before staging, it corroborates the source hash, record index, real offset, parser identity and timestamp. An opaque checked view ties the canonical encoding to an immutable event borrow. The writer reuses those checked bytes instead of serializing the same event twice; provenance, time and size checks remain in place. Canonical JSON orders every object recursively and uses checked integer timestamps. Enabling `serde_json/preserve_order` cannot change it.

Two additive parser methods emit common reader/local-file reports. Their defaults lift the unchanged historical indexed output. The bridge does not inspect field names or source words to infer classifications or roles: category/type sets are empty, outcome is unknown and old entity observations remain explicitly unspecified. Normalization never removes taint or extends permissions.

A module can override `StreamingEventParser::parse_common_reader_report` and `parse_common_local_file_report`. Build an `EventOrigin` from the supplied source hash and real record reference, insert checked fields into `EventContextV1`, and construct `EntityObservation` values with explicit roles and identity scopes. `CommonEventV1::try_new` checks that observations match the typed context. Emit the complete `CommonGraphRecord` inside its original `Tainted` provenance. The storage boundary independently corroborates that identity before writing. The [synthetic mapped parser](../../crates/infra/src/parquet_store/tests/common/mapped.rs) demonstrates this contract; it is not a production source mapping.

## Physical schemas and reconstruction

The V2 envelope and export V5 framing remain unchanged. New schema identifiers and the new builder `parquet-builder-common-event-v1` select the typed layout:

| Schema | Additional columns |
| --- | --- |
| `irmind-events-v4` | Category/type bitsets (`UInt32`), outcome/kind (`UInt8`), canonical common payload, observation-role membership (`UInt16`). |
| `irmind-entities-v4` | The same classification columns; role (`UInt8`), field code (`UInt16`) and canonical identity scope. |
| `irmind-coobservations-v3` | The entity columns plus scoped role/field peer descriptors. |

The event role mask supports filtering an event by a reported occurrence without an unbounded join. The legacy entity-pair projection remains available; it does not replace role-bearing observations. Roles label occurrences, not extra global nodes or directed attack edges.

Unknown codes, incompatible column types and schema/builder metadata mismatches fail validation. New envelope and payload goldens supplement historical fixtures; historical bytes are unchanged. Hash verification still precedes each Parquet read. Compaction and consolidation retain the validated common-schema file metadata; record batches alone do not carry that file metadata. Reconstruction chooses the builder recorded in the signed artifact and reproduces the complete artifact set.

V5 verification checks the common physical columns and file metadata after authenticating each derived frame's complete hash. A bounded file-range reader exposes only that frame to the Parquet reader; it neither extracts evidence to temporary storage nor reads neighboring frames. The direct `bytes` dependency supplies the return type required by Parquet's `ChunkReader` interface. The package is already present in the lockfile; no new package or feature is introduced.

Old store constructors keep their historical writers. `open_common` selects the new writer for new batched ingestion. Merely opening a case does not reparse its sources or change its generation.

## Queries and coverage

Existing tools accept optional `event_category`, `event_type`, `event_outcome` and `entity_role` selectors. Values come from closed enums; selectors combine with AND. CLI flags use hyphens; TUI graph commands accept `--event-category=authentication --event-outcome=failure`. Time, host and organization ceilings remain independent constraints.

Unclassified or historical records cannot match a classification or role they do not have. Filtered results explain incomplete schema coverage. A graph summary reports common, categorized and known-outcome counts. Absence of classified matches is not proof that the activity did not occur.

Entity lookup separates identity scopes and reports per-role observation counts. A PID without a lifetime identifier is source/record scoped; its reuse cannot bridge unrelated events. Same-value source and destination occurrences remain distinguishable, while event timelines deduplicate the source/record reference. Neighbor/path searches retain the existing 4,096-record sample, 3-hop, 200-expansion, 50-neighbor and 10-second budgets. Historical entity-only artifacts retain a bounded fallback.

## Compatibility boundary

No semantic migration is implemented. `CommonEventMigrationV1` is deferred. V1/V2 cases remain readable without migration; new semantic interpretation requires re-ingestion into a new case. The existing precision-only migration cannot activate a common-schema replacement.

Parser mappings, declarative mapping definitions and the Elastic/Chronicle connectors follow separately. A source alert never becomes a confirmed report finding automatically. Model-facing and terminal-facing projections still pass through the existing guard and redaction paths.

## Validation and measurement

Tests cover the codebook, canonical payload/envelope goldens, invalid typed values, same-value roles, PID reuse, the unclassified bridge, mixed readers, custody, public-key-only V5 verification and deterministic reconstruction. The shared parser contract checks deterministic common emission and cancellation. The preserve-order job also runs common goldens and bridge contracts.

Format tests exercise every closed context-field type and all identity-scope encodings in both JSON map modes. AddressSanitizer runs record their source revision, duration and execution counts for the [canonical codec](benchmarks/common-event-core-fuzz.json) and [export verifier](benchmarks/common-event-export-fuzz.json).

The manual graph benchmark supports a paired common-schema run against a pinned baseline: three smoke repetitions for representative cloud and endpoint sources, then one 15 GB pass per cloud/endpoint scenario on the same runner class. Builds use release optimization. The existing ingestion/query gates are unchanged. The bridge benchmark measures the core; it does not claim the cost or classification coverage of future source-specific mappings.
