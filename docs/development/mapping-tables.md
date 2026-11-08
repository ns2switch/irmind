# Declarative source mappings

This page is for mapping authors and maintainers. It describes the opt-in table interpreter in the common-event core; it does not enable source-specific semantic mappings by default.

A parser decodes original fields into `SourceRecordV1`. A mapping interprets those fields. See the [approved boundary](source-mapping-design.md) and [core custody](common-event-core.md).

## Definition and identity

`irmind-mod-mapping-tables` uses only the existing TOML/Serde stack. It accepts at most 64 KiB of input and canonical definition content. Unknown keys and values fail validation. The canonical definition is a strictly typed JSON structure with fixed field order; map insertion-order features cannot change its digest. TOML formatting does not determine its identity.

A definition names its ID/version, `irmind-common-event-v1` target, `irmind-source-record-v1` input contract, parser and explicit parser versions. Optional exact format, dataset, provider, channel and record-type selectors restrict it. The immutable mapping identity includes the canonical definition SHA-256 and interpreter contract `irmind-mapping-tables-v1`.

The [synthetic fixture](../../crates/modules/mapping-tables/tests/fixtures/synthetic-status.toml) demonstrates finite status rules and the same IP value in source/destination roles. It is test data, not a bundled forensic rule.

## Closed operations

Rules have at most eight conjunctive source-path predicates. Predicates are missing, null, present, exact typed text/boolean/number, or a closed integer interval. Literal dotted keys are distinct from nested path segments. At most 256 rules and a total 8,192-instruction budget apply. Overlapping rules and mapping selectors are rejected before activation, without a priority fallback.

Rule constants choose only closed category/type/outcome/kind codes. Missing or unrecognized status has unknown outcome unless an explicit missing/null rule says otherwise. The optional `action` path copies the original operation name without classification by text.

Fields copy one explicit source path into one closed CommonField. They can be global or specific to a rule; duplicate destinations are rejected. Conversions are checked copies, decimal/hex integers, IPs, domains and known-length hashes. List copies are bounded. A field cannot rewrite the source timestamp or origin. Compound DNS-answer and secondary timestamp transformations are not part of this interpreter version.

An optional observation declares its entity kind, role and scope. Scope is global only for domain-approved global identities; otherwise it comes from one explicit account/host field or the source/record reference. A process without a lifetime remains source/record scoped. Domain constructors independently check kind/role/field compatibility, identity scope and the complete event.

Optional host or account/region partition paths are source-derived data. The storage adapter applies the existing normalization, cardinality caps, safe path encoding and overflow policy; a definition cannot supply a directory name or change those limits.

There are no expressions, regular expressions, templates, arbitrary joins, environment lookups, scripts, network access, clocks or mutable global state. Invalid source values yield an explicit unsupported/unclassified diagnostic through the catalog. Invalid definitions or output fail the source transaction.

## Trust and versions

Bundled definitions require a digest pinned by the trusted binary. Installed definitions require an attended analyst's signed global operation containing their complete canonical content. Installation, activation, replacement and disable all build and validate the effective selection first. A failed preflight writes no operation. Reusing an ID/version for changed content is rejected.

Signed operations retain immutable historical content. A new ingestion uses the latest active selection; reconstruction uses the exact signed historical authorization and locally supported interpreter. An export carries the necessary proof without exporting unrelated global operations. Metadata authentication does not execute the definition.

The pure interpreter shares the decoder/mapping contract suite with native modules. Tests cover repeated/parallel execution, provenance, cancellation at the wrapper, finite statuses, same-value roles, absent values, native/declarative equivalence, overlap rejection, tampering and export verification without a keyring.
