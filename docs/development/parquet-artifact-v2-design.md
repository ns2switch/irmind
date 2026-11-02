# Proposal: precise event time in Parquet artifacts

This document is for maintainers reviewing [issue #143](https://github.com/ns2switch/irmind/issues/143). It proposes a new artifact envelope and timestamp schema. **It is not approved for implementation.** Existing source manifests, audit entries, seals, exports and Parquet files remain unchanged until the analyst approves this design.

## Problem and current behavior

`GraphRecord.at` currently carries an RFC 3339 string. The Parquet writer normalizes it with `SecondsFormat::Secs`, so the indexed `event_time` column loses fractions even when the original record contains them. Event, entity and co-observation tables all use that string. Several forensic events can occur in one second; their current display order cannot establish their original sequence.

Current schema names already include `irmind-events-v2` and `irmind-entities-v2`, together with `irmind-coobservations-v1`. Those names must never acquire new meanings. `ParquetArtifactV1` signs the file hash, source hashes, parser version, schema name and partition metadata. V2 source manifests already record parser selection and timestamp context.

## Goals

- Index UTC instants at microsecond precision and retain any finer source precision.
- Order equal instants deterministically by source and byte offset or record number.
- Read existing cases without rewriting them or inventing their missing fractions.
- Offer explicit, verified migration for open cases whose originals remain available.
- Keep source bytes, hash verification, policy ceilings, cancellation and query budgets intact.
- Use the existing Arrow, Parquet and time dependencies. Add no production dependency.

## Timestamp semantics

Introduce a checked application value for an indexed instant. Its primary value is signed microseconds since the Unix epoch, including dates before 1970. Conversion uses checked integer arithmetic; decimal epoch values must not pass through floating point. RFC 3339 values require a timezone, unless the parser has an explicit analyst-approved source context. Reject invalid offsets, unsupported dates, leap-second ambiguity and overflow; count rejected records under the existing bounded report.

The accepted calendar range is years 0001–9999 in UTC. An absent source instant stays null, not zero. A supplied but invalid instant is a rejected record, not an absent time.

For source precision finer than microseconds, retain a nanosecond remainder from 0 to 999 alongside the microsecond value. For example, an EVTX 100 ns tick is representable without rounding; Zeek decimal seconds retain their fractional digits. Source precision greater than nanoseconds is not silently rounded: the parser must preserve the raw value and report that the normalized schema cannot represent it exactly.

Carry a precision marker (`second`, `millisecond`, `microsecond`, `nanosecond`, or `unknown`) and whether the timezone/date was inferred from explicit context. A coarse event is not presented as a measured microsecond instant. Do not infer precision from trailing zeroes: use the source format and the number of significant fractional digits it supplied.

The original timestamp and complete original record remain available through the source pointer. The normalized record retains the full timestamp representation so reconstruction does not depend on display formatting. Display uses UTC and enough fractional digits to represent the source precision; it labels inferred or coarse time.

## Proposed schemas

Use new names, because the existing event and entity V2 schemas already mean something else:

| Artifact | New schema name | Time representation |
| --- | --- | --- |
| Event records | `irmind-events-v3` | `event_time`: Arrow `Timestamp(Microsecond, UTC)`, nullable |
| Entity observations | `irmind-entities-v3` | Same time, linked to the event record |
| Co-observations | `irmind-coobservations-v2` | Same time, linked to the event record |

Each schema adds `submicro_nanos` (`UInt16`, nullable with the instant), `time_precision` (bounded enum), `time_inferred` (boolean) and `source_offset` (`UInt64`, optional). Keep `source_hash` and `record_index`; they remain the stable record identity. A byte offset is recorded only when the parser knows it. CSV records with embedded newlines, binary EVTX records and grouped audit events must not invent a line offset.

Entity and co-observation artifacts retain their current entity sort and Bloom-filter behavior. Timestamp predicates use the numeric column and row-group statistics. A time boundary is converted using checked integer arithmetic, with the same inclusive boundary semantics as the current filters. An exact boundary finer than a microsecond also compares the residual value. Partition dates are derived from the checked UTC instant, including an offset that crosses midnight; absent time uses the existing `unknown` partition.

All time-bearing rows for one record must agree. Verification rejects an event whose entity or co-observation row has another instant, precision or source identity.

## Signed artifact envelope

Add `ParquetArtifactV2` and a new typed audit kind with wire value `ParquetArtifactV2`. Its canonical tag is `irmind-parquet-artifact-v2\0`. Preserve all V1 wire values and decoders byte for byte. This proposal requires approval because it introduces a signed format and an audit identifier.

The V2 canonical fields, in order, are:

1. Relative slash-separated artifact path, size and SHA-256.
2. Parser identity/version and exact schema name.
3. UTC date, account/project and region partition values.
4. Sorted, unique source SHA-256 values.
5. Time-semantics identifier `utc-microseconds-residual-ns-v1`.
6. Stable-order identifier `instant-source-offset-record-v1`.
7. Builder version and a sorted list of the superseded artifact hashes, empty for new ingestion.

Reuse the existing length-prefixed canonical primitives, fixed-width integer encoding and strict trailing-byte rejection. Keep source-count, payload-size and path bounds. Keep the current 16 KiB payload ceiling, 128-source ceiling, 128-byte version identifiers, 64-character lowercase SHA-256 values and current validated relative-path/partition bounds. Bound superseded hashes to 128 sorted unique values and reject self-supersession. Golden bytes must accompany the implementation before changing any decoder. Do not overload the V1 `parser_version` or schema name to hide a different envelope.

The file hash authenticates the Parquet metadata and logical schema. Readers also require the logical schema to match the signed schema name and the time-semantics identifier. Unknown identifiers fail closed. Every artifact is hash-verified before reading; scan projection and predicate pushdown do not bypass that check.

SourceManifestV1 and SourceManifestV2 remain unchanged: original hashes, parser choices, provenance and any timestamp context retain their current meaning. Audit hashing/signatures and seal domain separation remain unchanged. Use a new export V5 magic/header for packages containing V2 artifacts or migration records, retaining the current bounded framing and explicit version dispatch. V5 admits both envelopes; V4 remains readable and writable for V1-only cases. An older verifier must reject V5 rather than omit an unsupported artifact. Keep the existing seal challenge and key fingerprint: its final audit hash commits the new typed events, while its manifest computation must explicitly include both artifact variants. Add golden seal-manifest tests for mixed cases.

## Stable ordering

For exact instants, compare:

1. UTC microseconds.
2. Submicrosecond nanosecond remainder.
3. Canonical signed source name, compared by UTF-8 bytes, then source SHA-256.
4. Byte offset when present; otherwise the stable record number.
5. Record number as a final tie-breaker.

A parser must either supply offsets consistently for a source or use record numbers consistently; never compare a byte count with a record number as if they had the same unit. Missing-time events sort after timed events. Preserve the query's existing direction and limit rules; the comparator supplies a stable tie-break, not a change from latest-first to earliest-first. Never use filesystem enumeration, hash-map iteration, thread completion order, random IDs or machine paths as ordering inputs.

A V1 second-precision instant is lifted into the reader as a lower-bound microsecond value with `second` precision. It remains visibly coarse. Its placement among finer events in that second is a deterministic display choice, not proof of forensic order. The UI and reports must not infer causality from this placement. Sources with identical timestamps use the same stable source/offset/record rule.

The timeline, search, entity first/last observation, neighbors, path traversal and graph summary must share this comparator and precision semantics. Entity sorting remains `(kind, value, source identity, record identity)` for pruning; query result time ordering is applied after scanning.

## Compatibility and migration

Readers dispatch by the signed envelope and exact schema name. They support V1 and V2 artifacts in the same open case. Reading a V1 file does not modify it, its signature, its source manifest, or the case chain. A source precision that was already lost in the old derived index is not reconstructed without its original.

Migration is an explicit analyst action:

1. Lock the open case and verify its complete signed chain and referenced artifact hashes.
2. Resolve every original from its retained copy or signed source manifest. Rehash and compare it; a missing or changed source stops migration before publication.
3. Reparse with an available pinned, precision-preserving parser version and declared timestamp context. Stage V2 outputs privately, with bounded batches, deterministic ordering and cancellation checks.
4. Verify source-to-record links, normalized timestamps and reconstruction of every staged artifact. Compare record identities/counts and all non-time query semantics with the old artifacts. A parser change that alters record meaning requires a separate explicit decision.
5. Sign the new V2 manifests and a typed `ParquetArtifactsMigrated` record linking old and new hashes in one atomic audit batch. Its canonical payload tag is `irmind-parquet-migration-v1\0`; it binds source hashes, old and approved replacement parser versions, old/new artifact hashes, builder and time semantics. The approved transformation may recover source timestamp precision, not change record identity or other normalized meaning. SourceManifestV2 retains the original parser selection. Reconstruction uses the replacement mapping explicitly signed in the migration record; old artifact verification keeps the historical mapping. Old signed manifests remain in the chain.
6. Publish only a fully committed artifact set. Readers derive the active set from signed supersession links and reject cycles, cross-source substitution or partial migrations. Reopening after a crash either uses the old complete set or reconciles the new committed set; it never silently mixes an unfinished replacement.
7. Verify the chain and new artifacts again, and show the migration result and any precision limitation to the analyst.

Keep old artifacts while any historic signed reference requires them. Cancellation or failure removes uncommitted temporary files and leaves the old set active. This proposal does not authorize deleting signed evidence or rewriting a seal.

Sealed cases stay immutable and remain queryable through the compatible V1 reader. Migration of a sealed case is out of scope; it cannot append to that case or silently replace its sealed artifact manifest.

## Parser transition

Until this design is approved and implemented, Zeek and other parsers retain the complete original timestamp in the normalized record and raw source. They must not claim the current second-resolution graph preserves subsecond order. The pending network-parser PR is not evidence that this issue is resolved.

The common normalized event will need additive, typed time metadata and optional source offset, with compatibility constructors for existing parsers. The exact port changes and parser-version increments must be reviewed before implementation. Existing timestamp context continues to distinguish explicit timezone/year input from a measured instant. Do not infer a timezone or a missing RFC 3164 year silently.

## Required evidence before merge of an implementation

- Golden V1 canonical bytes remain unchanged; V1 cases and exports verify without migration.
- Golden V2 canonical bytes and file hashes match across Linux, macOS and Windows. Unknown units, malformed schemas, overflow, duplicate/superseded source links and trailing payload bytes fail closed.
- Events in the same second are ordered at microsecond precision; 100 ns EVTX ticks and Zeek decimal epoch fractions retain their residual precision. Include negative epoch values, UTC offsets across midnight, missing time, inferred context and rejected leap seconds.
- Equal-time records from different files have one reproducible source/offset order under parallel ingestion. Mixed V1/V2 results show coarse precision instead of invented fractions.
- All graph queries use the same time filter semantics and existing result, hop, expansion, sampling and time limits. Hash checking still precedes Parquet access.
- Migration tests cover every crash boundary, cancellation, missing/changed originals, parser-version mismatch, sealed cases and before/after chain verification.
- Run the existing deterministic HuntEval evaluation, network-parser fixtures, 1 GiB throughput and 15 GB query benchmarks. Compare latency and disk overhead; do not relax budgets or omit a query to meet the target.
- Extend bounded canonical/export fuzz targets for V2 and mixed cases. Keep source data untrusted through the guard and provenance path.

## Approval requested

Approve or amend the numeric microsecond column with an exact nanosecond remainder, the new envelope/schema identifiers, the stable ordering rule, mixed-version reads and the explicit open-case migration protocol. No implementation is authorized by this document alone.
