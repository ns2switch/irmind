# Proposed declarative parser examples

These examples are for contributors reviewing the [declarative parser design](../../development/declarative-parser-design.md). They specify the proposed syntax; they are not executable until that parser is implemented and tested.

- [CSV access events](access-csv.toml): an exact header and named columns.
- [Nested NDJSON authentication](nested-ndjson.toml): JSON Pointer paths and required fields.
- [Regex authentication lines](auth-regex.toml): bounded linear-time expressions and named captures.

All examples describe synthetic formats. They need no credentials and perform no I/O or network access. A definition cannot raise parser limits or tool permissions.
