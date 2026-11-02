# Proposal: precise event time in Parquet artifacts

This document is for maintainers reviewing [issue #143](https://github.com/ns2switch/irmind/issues/143). It proposes a new artifact envelope and timestamp schema. **The analyst approved the direction with the partition amendments below; this revision still needs review before implementation.** Existing source manifests, audit entries, seals, exports and Parquet files remain unchanged. This PR changes documentation only.

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
3. UTC date and a bounded, sorted list of generic scope key/value pairs, with the versioned key set and overflow semantics defined below.
4. Sorted, unique source SHA-256 values.
5. Time-semantics identifier `utc-microseconds-residual-ns-v1`.
6. Stable-order identifier `instant-source-offset-record-v1`.
7. Builder version and a sorted list of the superseded artifact hashes, empty for new ingestion.

Reuse the existing length-prefixed canonical primitives, fixed-width integer encoding and strict trailing-byte rejection. Keep source-count, payload-size and path bounds. Keep the current 16 KiB payload ceiling, 128-source ceiling, 128-byte version identifiers, 64-character lowercase SHA-256 values and validated relative-path bounds. Generic scope keys and values follow the normalization, cardinality and encoding bounds below. Bound superseded hashes to 128 sorted unique values and reject self-supersession. Golden bytes must accompany the implementation before changing any decoder. Do not overload the V1 `parser_version` or schema name to hide a different envelope.

The file hash authenticates the Parquet metadata and logical schema. Readers also require the logical schema to match the signed schema name and the time-semantics identifier. Unknown identifiers fail closed. Every artifact is hash-verified before reading; scan projection and predicate pushdown do not bypass that check.

SourceManifestV1 and SourceManifestV2 remain unchanged: original hashes, parser choices, provenance and any timestamp context retain their current meaning. Audit hashing/signatures and seal domain separation remain unchanged. Use a new export V5 magic/header for packages containing V2 artifacts or migration records, retaining the current bounded framing and explicit version dispatch. V5 admits both envelopes; V4 remains readable and writable for V1-only cases. An older verifier must reject V5 rather than omit an unsupported artifact. Keep the existing seal challenge and key fingerprint: its final audit hash commits the new typed events, while its manifest computation must explicitly include both artifact variants. Add golden seal-manifest tests for mixed cases.

## Generic scope partitions

Field 3 contains the UTC date plus `scope-partitions-v1` and at most five unique scope pairs. Keys are drawn from a closed set and sorted by their ASCII key bytes: `account`, `cluster`, `host`, `region`, `tenant`. `tenant` and `cluster` are reserved: current parsers must not emit them, and a future capability/key-set revision must explicitly activate them. Unknown keys, duplicates, an unknown version, or an unexpected reserved key fail closed; readers never silently ignore a key. Empty values are omitted, not interpreted as a wildcard.

Each parser declares its partition keys and their mapping as versioned capabilities, pinned by its signed parser version. Cloud parsers use `account` and `region`; `account` covers an AWS account, GCP project or Azure subscription. Endpoint and network parsers use `host`. A parser must not invent a host for telemetry that has none: leave the host partition absent and keep all observed source/destination hosts as columns/entities. A reviewed future parser may declare another supported combination; callers cannot inject arbitrary partition keys.

A partition is only an accelerator. Raw account and host values remain in the normalized record and as queryable entities. Scope authorization and row-level matching use the actual values, never a directory name or the overflow label. Mixed V1/V2 reads map legacy account/region metadata into the reader's generic representation without rewriting any V1 bytes. Missing keys and overflow buckets always remain eligible when pruning cannot prove that they exclude a query. A host filter must not discard cloud artifacts merely because their parser declares only account/region.

### Normalization and safe paths

Treat every partition value as tainted input. Normalize a copy of the value for partition bucketing only, using deterministic NFKC followed by locale-independent ASCII case folding. Pin the Unicode data version in the partition-policy identifier; a normalizer update requires a new identifier rather than silently changing historic bucketing. Reject control, bidi and zero-width characters, separators, URI syntax and path metacharacters. Require 1–128 ASCII bytes from `[a-z0-9._:@-]`, with an alphanumeric first character; reject `.`/`..` and a value that becomes empty or exceeds the bound after normalization. A value outside this naming subset routes to a signed overflow bucket with reason `unrepresentable-value`; it does not erase or alter the actual column/entity value. An invalid typed account or timestamp still fails the existing record validation.

Normalization may make two distinct raw values share a partition. This never merges their entities or changes exact query or policy semantics. Filter values use the same partition normalization, followed by exact row filtering. No untrusted value becomes a path component. For ordinary values, derive a lowercase SHA-256 directory component over a domain-separated, length-prefixed `(key-set version, key, normalized value)` tuple. Use only fixed key names and generated hashes in paths. Date components come from a checked UTC date. Overflow uses a separate typed discriminator, not a string a real host can impersonate. Retain path-length and no-follow checks on all platforms; hash-derived paths do not replace those checks.

### Cardinality and signed overflow

The initial hard ceiling is **1,024 distinct ordinary partition values per case and active key**, plus one typed overflow bucket for that key. Limits may be lowered by an approved configuration, never raised past the hard ceiling. Field 3 signs the partition-policy identifier, effective cap and the literal-or-overflow discriminator for each pair. Overflow signs its reason (`cardinality`, `tuple-budget` or `unrepresentable-value`) and cap; no new free-form sentinel string stands in for a host.

Assign ordinary slots in canonical signed-source order and stable record order, independent of worker completion. A bounded coordinator makes parallel parsing produce the same assignments. Derive the existing allocation state from verified signed artifacts before incremental ingestion; the first committed assignments stay stable. Cancellation and rollback cannot consume unsigned slots. Reconstruction replays the same source order and signed policy. Verify rejects an ordinary assignment exceeding the cap or an overflow claim inconsistent with the deterministic replay.

Per-key caps alone do not bound a cross-product. Also bound active scope tuples per UTC date and simultaneously open writers. Propose **4,096 ordinary tuples per date** and reuse the current bounded writer pool; excess new tuples route to a signed all-scope overflow bucket for that date. Continue preserving the date and real values in columns. Count overflow coverage in graph summaries so the analyst can see reduced pruning. Apply existing artifact/count/size limits as well; do not create one tiny file per host/record/source when batches can be combined within the current signed-source ceiling.

A query for a host scans its ordinary host bucket, any applicable overflow bucket, artifacts with no usable host partition, and legacy artifacts whose metadata cannot prove exclusion. An unknown or invalid selector cannot be turned into an authorization wildcard. Hash verification still precedes reading every selected Parquet file. Partitioning never bypasses exact filters, result limits or the 10-second path budget.

## Disk and latency estimate against the 15 GB reference

These are **design estimates, not measurements of a V2 implementation**. The [recorded 15 GB optimized benchmark](benchmarks.md#sorted-entities-and-signed-co-observations) is the reference: 8,451,871,774 B of Parquet, including 5,723,788,884 B of co-observations; ingestion 447.208 s. Its p95 values are entity lookup 1.726 s, timeline 0.028 s, neighbors 0.578 s and direct path 0.617 s. The worst three-hop path took 10.056 s and correctly reported truncation. That cloud-shaped corpus has no endpoint-host partition, so it cannot by itself measure a host-partition gain.

The current second-resolution UTC string has 20 UTF-8 bytes plus a 4-byte Arrow offset per time-bearing row before Parquet encoding. A numeric microsecond value uses 8 bytes. New physical columns are `UInt16` remainder (2 B), `UInt8` precision (1 B), packed inferred flag (1 bit), and optional `UInt64` offset (8 B), plus applicable validity bitmaps. A first-order estimate is about **19.5–19.75 B versus 24 B per time-bearing row**, a saving of roughly 4.25–4.5 B/row in uncompressed Arrow buffers. If a source supplies no offsets, Parquet can encode its all-null offset column compactly. This is not a prediction of compressed file size: dictionaries, RLE, nulls, row-group headers and source precision distributions can dominate, particularly in this repeated synthetic corpus. The reference generator's base row is 1,495 bytes and fills each base file with 699 records; 1,000 files repeated 15 times give **10,485,000 noise events**, excluding the small HuntEval/worst-path additions. Applied to events alone, the buffer estimate is about **44.6–47.2 MB less**, not GB of compressed disk. Entity/co-observation multiplicities must be counted before projecting the full store. These counts are derived from the unchanged generator, not a V2 benchmark run.

| Component | Estimate or expected effect | Evidence required before implementation merge |
| --- | --- | --- |
| Event time | Integer projection saves about 16 B/row before added metadata; exact range predicates avoid parsing a time string. | Count event rows and measure compressed time-column bytes, scan CPU and p50/p95 on the same 15 GB corpus. |
| New columns | About 11.5–11.75 B/row before compression for remainder, precision, inference, offset and validity; repeated precision/inference should compress well, but no ratio is assumed. | Report each new column's compressed/uncompressed size and null rate separately. |
| Entities and co-observations | The same time metadata repeats per observation. Co-observations are already 67.7% of disk; this proposal does not implement issue #37's record-ID/dictionary redesign. Their row count can dominate any timestamp saving. | Record event/entity/co-observation row counts and file sizes. Estimate `sum(rows_i * delta_bytes_i)` as a buffer bound and compare with measured compressed bytes. |
| Generic cloud partitions | The reference cloud workload still uses account/region, so key generalization should not deliberately change its grouping or fan-out. Added signed metadata grows at most by a few KiB per artifact under the existing payload ceiling. | Report artifact count, total signed-manifest bytes and p95 entity lookup against 1.726 s. |
| Host partitions | A filtered lookup may prune most of H ordinary host buckets, but must also scan overflow and legacy/unknown coverage. A query without a host filter gains no partition pruning and may slow from file fan-out. | Run host-filtered and unfiltered entity lookup, with complete hash verification, at 1, 64, 1,024 and 1,025 hosts. |
| File count | With D populated dates, one host key has at most `D * (min(H, 1024) + 1)` buckets, before bounded file rollover. Three artifact families and source batches can multiply files; the tuple/writer/artifact limits and existing compaction must bound this cost. | Report buckets, event/entity/co-observation files, median/p95 file size and overflow fraction; include skew and many tiny source files. At one date and 1,024 ordinary hosts, even one file per artifact family is about 3,072 files before overflow/rollover, so the hard cap is not a recommended partition count. Benchmark lower caps (for example 64) and require a reviewed, lower default if file-open/hash overhead outweighs pruning. |

For a uniform, host-filtered variant with H populated hosts and no overflow, the ideal scan/hash component scales roughly as `selected_bytes / H`; fixed manifest/file-open work does not. Dividing the 1.726 s reference by 64 or 1,024 gives 0.027 s or 0.0017 s **only as an idealized arithmetic lower bound**, not a predicted p95: the cloud corpus, existing Bloom pruning and host workload differ. With an overflow fraction q, the remaining byte fraction is at least `q + (1-q)/H`. For unfiltered queries q is effectively 1 and no such saving applies. Use the measured cost model `T ≈ fixed + opened_files * open_cost + hashed_bytes / hash_rate + decoded_rows / scan_rate` to turn the host-variant measurements into a forecast; do not invent a runner's file-open latency or compressed column ratio.

Repeat the unchanged 15 GB cloud/HuntEval benchmark and a **separate 15 GB endpoint/network variant** with the same byte/record-size distribution and controlled host cardinality. Compare against the current implementation on the same runner class and report p50/p95, selected files, hashed bytes and actual file count for every query. A host-specific entity lookup should improve only when its selector allows pruning; never present a filtered result as an unfiltered speedup. Keep existing query budgets and partial/truncated labels. More than 25% unfiltered latency regression, or any p95 above its unchanged budget, needs explanation and a reviewed remedy rather than a relaxed limit. Do not claim a disk saving or issue #37 closure until measured.

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
- Golden-test the generic key-set version, key ordering and reserved-key rejection. Test normalized collisions, malicious path values, long names, cross-platform directory encodings, and literal values resembling overflow labels.
- At the cardinality boundary, 1,024 ordinary hosts remain ordinary and the next distinct host enters signed overflow. Reordering workers cannot alter assignments. Failed/cancelled batches consume no slots, and reconstruction reproduces overflow and row-level query results.
- Host-filtered, unfiltered, missing-key, overflow and mixed V1/V2 queries remain semantically equivalent. Check tuple-budget overflow, file/writer bounds and actual values retained as entities. Run the 15 GB size/latency comparison above, including the many-host and tiny-file cases.

## Approval requested

Review this amended design, especially the generic scope-key version, 1,024-value cap, typed signed overflow, safe hash-derived paths and 15 GB estimate/measurement plan. The previously approved microseconds/residual, precision markers, stable ordering, mixed-version reads, explicit open-case migration, export V5 and original test criteria are retained. Stop here: implementation still needs the analyst’s approval of this revised document.
