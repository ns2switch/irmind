# Per-ingestion parser time context

This design is for maintainers reviewing the approved syslog correction and its reuse by the Linux parser. The implementation and validation are tracked in [PR #162](https://github.com/ns2switch/irmind/pull/162).

## Optional parser capabilities

The implementation adds these object-safe methods to the existing `LogParser` port. Existing parsers keep defaults: no context requirement, and an error if unsupported context is supplied.

```rust
fn time_context_requirement(
    &self,
    source_name: &str,
    sample: &[u8],
) -> Result<Option<ParserTimeRequirement>, AppError>;

fn with_time_context(
    &self,
    context: &ParserTimeContext,
) -> Result<Arc<dyn LogParser>, AppError>;
```

`ParserTimeContext` is a validated, immutable value: first source-calendar year (1–9999), fixed UTC offset in minutes (less than 24 hours in magnitude), an explicit December-to-January rollover choice, and a closed basis enum (`Analyst`, `Command`, `ConfirmedSuggestion`). No parser except syslog and Linux changes version. Requirement metadata identifies the needed fields; any host or source value derived from the sample remains tainted with sample provenance. Detection still receives at most 64 KiB and does no I/O. These types are application data, not new signed wire formats.

The module creates its configured parser and canonical version. The TUI and CLI do not construct syslog-specific parser instances or interpret parser-version syntax. Linux authentication input will use the same application flow.

## Analyst flow

1. Detect and select the parser through the existing registry.
2. Ask for the first record's year and fixed UTC offset when the selected format requires them. Show rollover enabled, with a visible choice to disable it. Allow one confirmed context for all files or separate contexts per file.
3. Show suggestions only when they can be linked to verified signed sources for the same logged host. Identify the source and inference basis. Suggestions are not automatically accepted; do not use the wall clock or file mtime. Do not parse human-readable graph output as a trusted metadata protocol. If a typed host/source lookup needs a separate port extension, propose it before changing that port.
4. Create immutable parser instances using the confirmed context. Group ingestion by parser identity and version, rather than parser name alone, so files with different contexts cannot share a parser accidentally.
5. Record the existing source selection plus canonical temporal context. The year and UTC-offset options of the ingest command follow the same validation and custody path. Missing context in unattended mode rejects ingestion and records its reason.

All forms stay inside the TUI, use the existing guard/escaping and reserved keys, and preserve entered values on validation errors. No named-zone support or timezone dependency is added; see [issue #161](https://github.com/ns2switch/irmind/issues/161).

## Calendar rule

Track local source-calendar month and year per file, independently of UTC conversion. Only a confirmed, enabled December-to-January transition increments the year. Reject any other backward month transition. When rollover is disabled, reject a backward boundary rather than silently assigning the wrong year. Check year overflow. Commit a proposed calendar state only after the complete record validates, so malformed records cannot advance the inferred year.

## Custody and compatibility

Keep SourceManifestV2 and ParquetArtifactV1 encodings unchanged. Bind the new interpretation in a new parser version and the existing temporal-context field, including the first year, fixed offset and rollover inference. Preserve the v1 parser and its exact fixed-year behavior for historical reconstruction, with all existing golden bytes and hashes unchanged.

Remove global legacy-year and offset settings from new ingestion. Previously signed configuration snapshots remain historical evidence; they must not become implicit defaults for a new ingestion. Existing active configuration requires an explicit, signed cleanup path or an actionable validation message, never silent acceptance or rewriting.

## Verification

Cover multiple per-file contexts, confirmed bulk application, signed same-host suggestions, unattended rejection, command flags, December/January rollover, other backward months, disabled rollover, malformed rows and year overflow. Verify v1 reconstruction after configuration changes and unchanged signed goldens. Repeat the 1 GiB end-to-end benchmark only in release mode after implementation; the ignored benchmark now rejects unoptimized builds.

## Retiring approved global configuration

Startup reviews old signed snapshots against the exact former syslog configuration schema, only at the composition root. This does not relax unknown-field or secret validation for any module. If the file differs from its approved snapshot, normal recovery runs first. The TUI then asks permission to remove the retired fields, recording each removal using the existing signed configuration operation and atomic writer. It never opens a case with global temporal defaults. The automation CLI refuses the retired fields and directs the analyst to the TUI. A crash between removals leaves the remaining field for another explicit review. Original operations and source manifests remain intact.

Same-host suggestions use graph text only to locate candidate pointers. Each candidate must match a signed SourceManifestV2, pass artifact verification, resolve the recorded parser version and re-extract the same host and its source-stated time from the actual raw record. Presentation strings are never accepted as trusted temporal metadata. Confirming or editing a suggestion sets the closed basis enum before the parser creates its signed version/context.
