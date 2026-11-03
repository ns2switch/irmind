# Declarative parser examples

These examples are for contributors and analysts preparing an exact custom export mapping. Use `/parsers` to preview and install a definition through the signed flow. Definitions need analyst selection on ingestion; their confidence stays below native detectors. See the [parser guide](../../parsers.md).

- [CSV access events](access-csv.toml): an exact header and named columns.
- [Nested NDJSON authentication](nested-ndjson.toml): JSON Pointer paths and required fields.
- [Custom HTTP export](nginx-apache-custom.toml): a custom nginx/Apache NDJSON export with explicit host. Adapt field paths to the exact export; configure JSON escaping at collection. Example: `{"custom_http":{"time":"2026-11-01T01:00:00Z","host":"synthetic-web","user":"synthetic-user","client":"203.0.113.77","method":"GET","status":"200"}}`. Native common/combined files use parser-linux.
- [Regex authentication lines](auth-regex.toml): bounded linear-time expressions and named captures.

All examples describe synthetic formats. They need no credentials and perform no I/O or network access. A definition cannot raise parser limits or tool permissions.
