# Syslog parser contract

This page is for parser maintainers and analysts validating synthetic syslog input. The experimental module decodes line-oriented RFC 5424 and RFC 3164 files, including gzip. It never executes a message, command, filename or structured-data value.

## Selection and time

`parser-syslog` is compiled by default and removable with a minimal build. Its pure detector reads at most 64 KiB of input. It checks PRI plus the timestamp/header shape, not the filename. RFC 5424 receives confidence 95 and RFC 3164 receives 90. A gzip sample expands at most 4 KiB for detection. The common registry still asks the analyst for ties or low confidence.

RFC 5424 retains its original offset and fractional timestamp in the raw record and a full UTC timestamp in normalized text. The existing V1 derived index remains second precision until the approved artifact-V2 work. A NIL timestamp remains unknown; no clock supplies a replacement.

RFC 3164 requires an explicit year and fixed UTC offset. Set both non-secret values together in `config.toml` and approve the changed configuration in the TUI before opening cases:

```toml
[modules.parser-syslog]
enabled = false # Parsers activate through detection, not remote connector enablement.
[modules.parser-syslog.values]
LEGACY_YEAR = "2026"
LEGACY_UTC_OFFSET_MINUTES = "60"
```

The module does not read environment variables or secrets. The composition root injects its configuration. Missing context rejects RFC 3164 records rather than assigning a year or zone. Each accepted legacy row has `timestamp_inferred=true`. The signed SourceManifestV2 records year, offset and analyst basis; the parser version also binds them. Historical resolution reconstructs that exact version after settings change. No automatic DST or new-year rollover is inferred. Use separate, explicitly configured ingestions for different years/offsets.

## Mapping and bounds

The normalized record retains raw text, full UTC time, inference marker, host, application/process, PID, facility, severity, message ID, structured-data text and message. It extracts host, process and PID entities. Structured data and message bodies stay data; this module does not infer confirmed findings or execute embedded JSON. The source hash and record number identify every row. Plain files keep the byte offset. Gzip rows use an unknown physical offset of zero and retain their exact decoded record number; they never claim an offset in the compressed file.

Limits are 1 MiB per line, ten million nonblank records, 50 GiB per plain stream, three rejected samples of at most 256 bytes, and 2 GiB each for compressed and decompressed gzip input. Oversized or malformed individual lines are counted and bounded samples are retained; subsequent records still parse. Invalid gzip headers, checksum failures and stream/size/cancellation errors reject the conversion, so the application never signs half a file. All parsed rows are Tainted with source provenance. Guard/redaction still apply when data reaches the model or terminal.

The common graph policy currently accepts a closed list of query entity kinds that excludes process/PID endpoints. Those entities remain available in host neighbors, source records and text search. This module does not widen the policy to make process path queries pass. Host partitioning follows artifact V2; it is not claimed for current V1 artifacts.

## Dependency review

The analyst approved adding `flate2` for gzip. Version 1.1.10 is pinned with defaults disabled and the explicit `miniz_oxide` feature. Its published archive SHA-256 is `6e634e2e0ebac1ee034020da1ca582e17ffe4e0f5e985823721e168928136dcb`; the review checked it before reading the source. The project has recent maintained releases and MIT OR Apache-2.0 licensing. This is dependency review evidence, not a complete security audit.

The selected backend needs no system zlib or C decoder. Required new packages are flate2, miniz_oxide, adler2, simd-adler32 and crc32fast; the lockfile pins their exact versions. Checksum acceleration can contain target-specific unsafe code, so the dependency closure is not described as entirely unsafe-free. IRMind's module forbids unsafe. The reviewed gzip header parser bounds filename/comment buffers to 65,535 bytes; IRMind additionally bounds stream input/output and tests corruption and cancellation. Cargo-deny must pass without new exceptions.

Sources: [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html), [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164.html), [flate2 documentation](https://docs.rs/flate2/1.1.10/flate2/), [upstream maintenance](https://github.com/rust-lang/flate2-rs).

## Validation

The shared parser contract, detection matrix, temporal context reconstruction and actual SQLite/Parquet ingestion tests use only synthetic source fixtures. Expected answers under the fixture's `private/` directory are evaluator-only. They are not ingested, evidence or model context. The fuzz target exercises detect and parse with both missing and explicit legacy context. The weekly workflow includes its versioned synthetic seeds.

Results and the 1 GiB end-to-end benchmark are recorded in [benchmarks](benchmarks.md) after execution. No live-device validation is claimed.
