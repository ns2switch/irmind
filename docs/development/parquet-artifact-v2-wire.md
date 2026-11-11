# Historical artifact V2 foundation and canonical layout

Historical design: standalone V2 artifacts and their fixtures are retired. Current V3 envelopes retain the nested metadata core, with the current common physical schema IDs. See [source mapping](source-mapping-design.md) and the [pre-1.0 decisions](decisions.md).

This page is for maintainers checking the first implementation of the [approved artifact design](parquet-artifact-v2-design.md). It fixes the golden encoding before a writer can publish V2 files. It does not activate V2 ingestion, migrate a case or change an existing signed byte.

## Indexed time

`IndexedInstant` holds signed Unix microseconds and a 0–999 nanosecond remainder. Checked UTC values span years 0001–9999. `IndexedTime` adds source precision and inference. Absence uses `Option`, never epoch zero. Existing `UtcTimestamp` and its signed representation stay unchanged.

Physical precision codes are `unknown=0`, `second=1`, `millisecond=2`, `microsecond=3`, `nanosecond=4`. A coarse marker cannot conceal finer nonzero digits. Decimal epochs use checked integers and Euclidean division, including before 1970. RFC 3339 requires an explicit timezone. Unknown `-00:00`, leap seconds, more than nine fractional digits and UTC-range overflow are rejected. The calling parser retains the original and counts a supplied invalid timestamp as rejected; it must not turn it into missing time. Fractional digit count determines the precision bucket, including trailing zeroes. Inference comes from explicit source context, never a machine clock.

## Canonical envelope

The tag is `irmind-parquet-artifact-v2` followed by NUL. Strings are UTF-8 with an unsigned 64-bit big-endian byte length. Counts and integers use unsigned 64-bit big-endian encoding. Boolean/discriminator fields use one byte. Hashes are length-prefixed 64-character lowercase hex strings. Strict decoders reject trailing bytes, invalid tags and noncanonical lists.

The seven groups retain the approved order:

1. Relative slash-separated path; size; artifact SHA-256.
2. Parser ID; parser version; exact schema name.
3. The partition block described below.
4. Source count and sorted, unique source hashes (1–128).
5. `utc-microseconds-residual-ns-v1`.
6. `instant-source-offset-record-v1`.
7. Builder version; superseded count and sorted, unique hashes (0–128). Self-supersession is invalid.

The binary payload stays within 16 KiB. Count limits do not permit exceeding that combined ceiling. Paths stay relative and at most 1,024 bytes, with at most 255 bytes per component. Derived paths use only lowercase ASCII letters, digits and `/._=-`; controls and user-provided names cannot enter them. Version identifiers are nonempty ASCII graphic text of at most 128 bytes. Parser IDs retain their 64-byte lowercase/digit/hyphen grammar. Unknown schema, time, order or policy identifiers fail closed.

The schema names are exactly `irmind-events-v3`, `irmind-entities-v3` and `irmind-coobservations-v2`. The typed audit kind is `ParquetArtifactV2`; previous kinds retain their wire strings. No source-manifest, audit-entry or seal encoding changes.

### Partition block (field 3)

The block contains, in order:

1. Checked UTC date (`YYYY-MM-DD`) or the existing `unknown` bucket.
2. Key-set identifier `scope-partitions-v1`.
3. Normalization-policy identifier `nfkc-unicode-18.0.0-ascii-v1`.
4. Date tuple cap, 4,096.
5. All-scope-overflow byte: 0 or 1.
6. Pair count (at most five), then pairs sorted by ASCII key bytes.

Each pair contains the key string, effective cap (1–1,024), discriminator, and value string. Discriminator 0 carries a normalized ordinary value; 1 carries a typed reason: `cardinality`, `tuple-budget` or `unrepresentable-value`. Reserved `cluster`/`tenant`, unknown keys, duplicates and unsorted pairs fail closed. The active keys are `account`, `host` and `region`. The initial host cap is 64; selecting the production default remains a release-benchmark task.

An all-scope overflow has a nonempty declared key list, with every pair explicitly marked `tuple-budget`. Individual caps and the date tuple cap remain signed. The foundation checks that ordinary strings are already in the approved bounded ASCII normal form. NFKC normalization and deterministic slot allocation belong to the separate partition-writer PR; they are not active here.

Ordinary directory components use lowercase SHA-256 over `irmind-scope-partition-v1` + NUL, followed by the length-prefixed key-set version, key and normalized value. Paths use `date=<date>/<key>=<hash>/.../<file>.parquet`. Per-key overflow uses a generated `overflow-<reason>-cap<cap>` component; all-scope overflow uses `scope=overflow-tuple-budget`. These are typed branches, never values that a raw host name can impersonate. The decoder checks the signed partition/path binding. Actual row values and authorization never depend on a directory component.

## Golden evidence and staged compatibility

The independently encoded [731-byte golden](https://github.com/ns2switch/irmind/blob/5905ed7d8334616fd43793a12b0d4aa4b5b45115/crates/domain/tests/fixtures/parquet-artifact-v2.hex) has SHA-256 `6808f98e727835b7ec24137c77c14391efc48ed4cb7832c9457c43e85d779f52`. It describes synthetic cloud event metadata, two ordinary scope pairs and no supersession. A separate Python `struct`/`hashlib` encoding produced the fixture; the Rust encoder must reproduce it exactly. Independent overflow fixtures also bind each reason and a supersession link. Domain tests cover unknown identifiers, trailing data, payload/count bounds, unsafe paths, reserved keys, caps, typed overflow and supersession.

This retired fixture was checked with `serde_json/preserve_order` when V2 was supported. Current golden and fuzz coverage uses the mapped V3 envelope, its nested current metadata cores and exact timestamp parsers.

Until the mixed reader/writer is implemented, the application and V3/V4 export verifiers reject a chain containing V2 rather than silently omitting an artifact. Production ingestion still emits V1. The mixed reader/writer, generic partition coordinator, explicit open-case migration/export V5 and release benchmarks follow in separate PRs. This foundation is not evidence that indexed timelines already preserve subsecond order.
