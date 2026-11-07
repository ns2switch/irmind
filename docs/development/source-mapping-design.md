# Source decoding and mapping modules

This design is for parser, mapping, connector and evidence-store maintainers. It separates faithful source decoding from forensic interpretation, so a new mapping or target schema does not require changing a parser.

**Status: proposal, not an implementation.** The [common-schema core PR](https://github.com/ns2switch/irmind/pull/205) remains separate. This document proposes new ports and signed records for review; it does not register them, change historical bytes, enable a provider or activate a writer.

## 1. Two stages, one explicit boundary

```text
bounded source handle -> format decoder -> Tainted<SourceRecordV1>
                                             |
                                  frozen mapping selection
                                             |
                                  pure mapping module
                                             |
                                  Tainted<CommonEventV1>
                                             |
                              validated Parquet projection
```

The engine owns handles, custody, quotas, cancellation, staging, scheduling and publication. A parser owns framing, decompression, character/binary decoding, source-field types, source timestamps and the already approved per-ingestion temporal context. A mapper owns field interpretation, classifications, outcome tables, entity extraction and roles. Neither a filename nor an analyst's case title supplies missing event values.

Parsing never creates a common category, outcome, actor/target role or attack edge. Recognizing the grammar of an sshd message, grouping auditd members by serial, or decoding an EVTX integer is format decoding. Deciding that the resulting record represents authentication failure, identifying the acting account, or assigning a process role is mapping.

Both stages retain taint. A successful domain constructor establishes representation validity, not truth, trust or permission. The existing guard/redaction boundary remains before model or terminal output; ingestion does not redact or rewrite the canonical source record. No source-derived content enters a system message.

### SourceRecordV1

Put checked source-value types in `irmind-domain`, and decoder ports/codecs in `irmind-app` and adapters. Do not use `serde_json::Value` as the domain contract.

| Component | Meaning |
| --- | --- |
| Contract | `irmind-source-record-v1`, plus a versioned source-format descriptor. |
| Identity | Source SHA-256 and the decoder's zero-based record ordinal; retain the current ordinal convention through a compatibility route. An EVTX EventRecordID is an original field, not this ordinal. |
| Provenance | Parser ID/version, original source reference, optional real offset, source kind and acquisition reference. Grouped records may carry bounded member references. Never invent a byte offset. |
| Time | Optional existing `IndexedTime`, including residual nanoseconds, precision and inference. Timestamp field selection and units belong to the format descriptor. RFC 3164 year/offset/rollover use confirmed signed context, never the machine clock or mtime. |
| Fields | Original names and typed values, with original array order. A source path is a bounded list of segments: a literal key `source.ip` differs from nested `source` / `ip`. No silent flattening or last-key-wins conversion. |
| Routing discriminators | Bounded format, dataset, provider/channel and native record-type values taken from documented source fields. These remain untrusted claims. They cannot name a module to load or an executable path. |
| Decode annotations | Explicit partial-group, inferred-time and declared-source-type markers; no inferred forensic result. Preserve a bounded raw-record reference. |

The closed value family covers null, boolean, exact integers/decimal-number lexemes, text, bytes, arrays and objects. Preserve a JSON number as a number, including its exact bounded decimal lexeme; do not round it through `f64` or turn a numeric-looking source string into a number. CSV values stay strings unless the source format declares a type; Zeek TSV and OCSF Parquet retain their declared types. Preserve unsupported binary/Arrow representations as bounded tagged source values or reject them explicitly, rather than silently converting them.

Canonical source encoding sorts unique object keys by UTF-8 bytes and preserves array order and primitive type tags. Duplicate keys are rejected under the new source contract. Canonical record hashes cannot depend on `serde_json/preserve_order`. Original bytes remain authenticated by their separate source hash; decoded records do not reproduce original whitespace or byte order.

Effective limits are the smaller of the existing parser limits and the source-contract ceiling. Proposed ceilings are 4 MiB per encoded record, 4,096 field/value nodes and 32 nesting levels. Exact source-number lexemes are at most 128 bytes. These are proposed new-contract bounds, not permission to increase any current limit. Oversized or malformed records retain the existing rejection counts and bounded tainted samples. A large monolithic document is streamed record by record; its first line is not a record-size limit.

### Pure mapping and the storage adapter

A mapping is semantically `SourceRecord -> CommonEvent` for one explicit target schema. It receives only a bounded record view and immutable compiled tables. It has no file/network/secret ports, clock, case configuration, mutable global state, tool calls or randomness. It cannot manufacture a different origin or timestamp. The engine independently corroborates origin, record identity and time before writing.

An operational result also carries bounded diagnostics and, where required, the existing role-free search projection. That projection is produced **by the mapping module**, never by a new parser. It reuses #205's application-level `CommonGraphRecord`/legacy-pair view without changing the logical `CommonEventV1` contract or its codes. It is labelled unspecified; it cannot create a typed role, a global PID identity or a confirmed finding.

This distinction matters for incremental delivery. An explicitly installed extraction-only mapping can preserve today's role-free entity/search behavior while returning empty category/type sets and unknown outcome. It is still a mapping with its own signed identity. With **no** matching mapping, the built-in unclassified constructor retains time, origin and original-record reference, with no guessed entity extraction. Search and timeline remain available; absent graph coverage is reported. Benchmarks must not claim equivalence by querying an empty unclassified graph.

Mapping modules use the existing validated common constructors and their 64 KiB projection, 32-observation and field-specific limits. Missing/unsupported statuses map to unknown only through an explicit finite rule. A declared data-validation failure may produce an unclassified record with a fixed diagnostic; it cannot produce a partially trusted classification. Invalid module output, an invalid definition or registry ambiguity fails the source transaction closed. The writer never works around an invalid common event. Every accepted source record must have exactly one event projection, mapped or explicitly unclassified.

Cancellation is checked outside the pure call, between bounded records/batches. Deterministic operation budgets bound a single call. Local work runs through the existing `spawn_blocking` use cases. Source-start ordering, EVTX containment and `SourceParallelism` remain unchanged.

## 2. What moves out of existing parsers

The table concerns new source-record ingestion. Published historical projections remain pinned as described in section 6.

| Parser/source | Stays in decoding | Moves to independent mapping |
| --- | --- | --- |
| Generic JSON / CloudTrail / cloud exports | JSON framing, wrappers, original typed fields, exact time/offset and source-format detection. | Current action aliases, entity extraction, account/resource interpretation and relations; CloudTrail outcome, category and principal roles. Generic unknown JSON has no semantic inference. |
| HuntEval normalized JSON | Public `source/events.json` fields and types, event time and IDs. | Principal/account/resource/IP observations and relationships. Private expected answers remain evaluator-only. |
| ECS | JSON/NDJSON records, literal-versus-nested keys and original values. | ECS field-to-common assignments, closed label validation, result and source/destination/actor roles. |
| OCSF JSON / Parquet | Bounded streaming/random access, physical types, timestamp units and original UID/version fields. | Class/category/status tables, actor/target/process/network meanings. |
| Velociraptor | Rows, column metadata, `_Source`/Artifact and source time. | Artifact-specific user/process/file meaning and role assignment. |
| Hayabusa | CSV/JSONL grammar, native columns, timestamp and record references. | Detection descriptor, severity interpretation and linkage to an event; no automatic confirmed finding. |
| Chainsaw | Hunt/search containers, original event fields and timestamp. | Hunt annotations, action/entity projection and Windows semantics. |
| plaso | JSONL, source `parser`/`data_type`, source precision. | Data-type-specific observation meanings; a filesystem timestamp does not imply execution. |
| EZTools | Exact tool headers, cell types and original timestamp columns. | Tool-specific file/process/registry/usage interpretation and role-free/typed entities. |
| Zeek | `#fields`/`#types`, escapes, JSON, exact decimal `ts`, UID and native fields. | Originator/responder roles, protocol/event categorization and any finite result table. UID remains source/sensor-scoped. |
| Suricata | EVE framing, exact timestamp, native `event_type`/flow ID and fields. | Alert/flow/protocol semantics, rule descriptor, endpoint roles and outcome. Blocking is not automatically failure. |
| Syslog | RFC headers, PRI/facility/severity, structured data, app/PID, original message, gzip and confirmed legacy-time context. | Current emitter entity projection and any application-specific classification. Severity is not outcome; emitter PID is not a subject process. |
| Linux auth.log / secure | RFC 3164 context and supported sshd/sudo/su/useradd/usermod/cron message grammar, preserving original token values. | Accepted/failed result tables, action aliases, actor/attempted/target/effective user and command meaning. |
| Linux auditd | Bounded serial grouping, original members/arguments, CWD/PATH/sockaddr decoding, precise epoch and partial markers. | Syscall/action families, `success`/`exit` interpretation, auid/effective user and process roles. |
| journald | JSON fields and complete microsecond `__REALTIME_TIMESTAMP`. | `_TRANSPORT`/unit-specific meaning and user/process projection; priority is not outcome. |
| nginx / Apache | Common/combined tokenization, escaping, request components and explicit timestamp/offset. | HTTP result table, client/authenticated-user roles and web categorization. |
| EVTX | Existing isolated helper/protocol, binary/XML decoding, original provider/channel/fields, real record ID/offset and 100 ns time. | `event_name`, the current `normalize.rs` field selection, success/failure rules, entities/relations and provider+channel+EventID mappings. Helper isolation does not change. |
| Declarative parser | Signed framing/detection definition, CSV/JSON/regex capture grammar, declared source types and time context. | Common-field assignments, categories, finite outcomes and entity roles move to a separately installed mapping definition. |

Text formats need stable format-specific field names where no original key exists, such as a syslog header token or an sshd user token. The source-format descriptor records that grammar and its version. Such names must not pretend to be normalized ECS fields.

Existing declarative definitions keep their original parser identity and historical combined behavior. New decoding definitions and mapping definitions have different IDs, hashes and installation operations. Changing a mapping cannot change a parser's detection, framing or temporal context.

## 3. Mapping modules and deterministic selection

### Identity and packaging

`MappingIdentityV1` contains a bounded ID, exact version, target schema ID and immutable implementation/definition SHA-256. Its manifest declares accepted source-record contract versions, parser IDs and explicit supported parser-version sets/ranges, plus bounded dataset/channel/native-type selectors. Prefer explicit supported-version sets. A declared SemVer range is allowed only for a decoder that actually uses SemVer; other bounded ranges must resolve to an explicit set of registered named versions when the catalog is frozen. Source names such as `json-stream-v3` are not assumed to be SemVer. An unresolved version is an error, not a match.

Preserve frozen historical projection code rather than changing a shared helper and silently changing an old parser identity. New source-specific interpretation belongs only to its mapping crate.

Native modules live in independent crates such as `crates/modules/mapping-cloudtrail/`, behind individual Cargo features, and register through the composition root. They depend inward on the application/domain contracts, not on another adapter or its HTTP SDK. They receive no credentials. Their digest comes from a canonical build manifest covering mapping sources/tables, manifest, enabled production features and resolved production dependencies; no absolute build paths enter that digest. A changed digest requires a new mapping version. Native mappings are reviewed compiled code, not dynamically downloaded executables.

Declarative mappings are TOML data interpreted by one optional mapping-module crate. They allow only checked field copies/renames, closed constants, finite typed equality/status tables, role assignments to the closed common-field list and a small versioned list of checked primitive conversions. No arbitrary expressions, scripting, regex, filesystem references, queries, templates, network operations, loops or model prompts are permitted. Interpretation has no dependencies beyond crates already used by the workspace; any implementation needing another dependency requires separate review.

An illustrative rule, not an installed definition:

```toml
id = "mapping-evtx-security"
version = "1"
target_schema = "irmind-common-event-v1"
source_contract = "irmind-source-record-v1"
parser = "parser-evtx"
parser_versions = ["evtx-0.15.1-ndjson-v1"]
channel = "Security"
provider = "Microsoft-Windows-Security-Auditing"

[[rules]]
event_code = 4625
categories = ["authentication"]
types = ["start"]
outcome = "failure"

[[rules.fields]]
source = ["Event", "EventData", "TargetUserName"]
target = "user.target.name"
role = "target"
```

The compiler checks this against the exact source schema and domain constructors; missing fields do not acquire invented defaults. It does not assume this example covers every Windows event version. Scope construction uses explicit validated source fields, or source-record scope where appropriate; a PID cannot become a global node.

Proposed definition limits are 64 KiB canonical content, 256 rules, 256 status entries per table and 32 path segments, with an additional total instruction budget. All output limits remain the domain's existing limits. Unknown keys, enum values, ambiguous source paths and invalid primitive conversions are rejected before activation.

### Signed installation and historical versions

Use the same custody pattern as parser definitions: analyst-signed global operations install/replace/disable a definition, binding its exact canonical content and hash. Keep immutable content-addressed historical versions and the interpreter contract version. Paths use generated hashes and private case/data permissions; definitions never come from evidence paths or model output.

At startup, validate configured definitions against their signed copies. A manipulated definition is disabled with a visible diagnostic; it is not silently restored or replaced by another mapping. Previously signed case generations remain authenticatable. Rebuild requires the exact historical definition/interpreter or native implementation; it never substitutes the latest version. Definitions remain untrusted content for display and model contexts even after installation.

### Selection algorithm

1. Snapshot the enabled mapping catalog and explicit active versions before ingestion; hash the canonical snapshot.
2. Run the existing parser-detection registry and analyst ambiguity flow. Only the selected decoder receives the bounded source handle.
3. For each decoded record, match parser/version and typed dataset/channel/provider/native-type selectors against that snapshot. Input values can select only already registered, enabled entries.
4. Exactly one eligible mapping runs. Zero matches uses the explicit unmapped projection. Two matches stop that source with a visible configuration error, even if outputs might be equal.
5. There is no highest-priority, most-specific, first-registered or latest-version fallback. An analyst resolves overlap by a signed configuration change before retrying.

Extraction-only and semantic versions of the same route cannot both be active. A semantic mapping replaces the selected route explicitly; it does not silently outrank a generic mapping. Catalog selection is frozen for the ingestion, so an installation in another session cannot change half a file.

### Shared contracts

Every native and declarative mapper passes one suite: exact output/golden codes; bounded execution/allocation; deterministic repeated/parallel execution; map-order independence; origin/time preservation; taint retention; missing/unknown outcomes; same-value source/destination; distinct actor/target; account collisions; PID reuse; invalid values and definitions; no-match behavior; ambiguity; tamper disabling; exact historical replay; cancellation/rollback at the wrapper; and no content-bearing Debug/errors. Native and declarative versions of a synthetic rule must produce identical canonical events.

Injection-shaped field values remain data and cannot select uninstalled code, emit a tool call or grant a permission. Include the existing obedient-fake-model test after mapped output passes through the guard. Native mapping dependencies and implementations receive purity/bounds review; the declarative grammar cannot express I/O.

## 4. Independently versioned target schemas

The first target remains `irmind-common-event-v1`, derived from ECS 9.5 with its frozen codes and constructors. Mapping version changes do not change that schema. A source parser need not know which target consumes its records.

A future ECS 9.6-derived `irmind-common-event-v2` has its own domain types, code table, encoder and mappings. It does not mutate V1. A mapper declares exactly one target; shared Rust helpers may support separate mapper registrations. A new target gets distinct physical IDs whenever codes or meanings differ, even if column types happen to be identical. The approved V1 physical IDs are not reused with different semantics.

One case may contain active sources mapped to different targets, plus historical V1/V2 artifacts. Query adapters translate a requested semantic selector through each target's explicit compatibility table. Unsupported selectors never become unfiltered scans. Results include coverage: sources/records matched, unmapped, legacy, excluded by target or unavailable for that selector. Unknown schema identifiers fail closed; known but unclassified input is valid.

Default queries use one active generation per source-record set and deduplicate event references by the immutable source/ordinal key. Keeping V1 and V2 target generations for comparison must not double-count events. Cross-target entity merging requires an explicit lossless identity-compatibility rule; equal strings alone are insufficient. Role membership is not a directed attack edge.

All targets share the existing total query deadline, result/token bounds, 4,096-record neighbor sample, path hops/expansion bounds and partial markers. They do not each receive another ten-second budget. Filters and schema coverage remain available through the existing graph tools/cards.

## 5. Custody: explicit fields, not overloaded versions

The [V2 envelope](parquet-artifact-v2-wire.md) has seven closed groups and no extension map. Its parser/version and builder identify different responsibilities. Neither can honestly encode a mapping version, target schema or selection snapshot.

**Recommend a new `ParquetArtifactV3` envelope**, with its own `irmind-parquet-artifact-v3` domain tag. Preserve the existing V2 fields and add a distinct bounded pipeline block:

| New field | Binding |
| --- | --- |
| Stage | Decoded-source cache or mapped projection. |
| Source contract | Exact `irmind-source-record-v1`/format-contract identity and digest. |
| Target schema | Explicit logical schema ID and contract/code-table digest; absent for decoded-source artifacts. |
| Mapping identity | ID, exact version, implementation/definition hash; an explicit unmapped discriminator when no mapping ran. |
| Catalog/profile hash | Frozen selector/version/configuration snapshot, including the pinned interpretation policy. |
| Input set | Source-record-set count/commitment and the signed decoding snapshot reference. |
| Mapping profile reference | Hash of the input/target/selection profile, computed without output or receipt hashes; required only for mapped artifacts. |

The parser version continues to describe decoding; builder version describes physical writing only. A mapping update changes mapping fields, not either of those versions. Keep the existing 16 KiB envelope ceiling, list bounds, safe paths and canonical length-prefix rules. Split artifacts/manifests when needed rather than raising limits.

Add proposed signed `SourceRecordSetV1`, `MappingProfileV1` and `MappingRunV1` events. The former binds source-manifest hashes, exact decoder/time context, accepted/rejected counts and a canonical record-set commitment. `MappingProfileV1` freezes the input-set reference, target, mapping identities, catalog and interpretation policy, without output hashes. The final `MappingRunV1` receipt binds that profile, actual used mapping identities, per-route counts, mapped/unclassified diagnostics and complete output-envelope commitments. V3 artifacts reference the profile, never the final receipt: the receipt hashes the artifacts, so a reverse reference would be circular. A complete atomic batch must contain the profile, all declared artifacts and its final receipt. Decoded caches reference only the signed source-record set and decoding contract, not a mapping profile, so another mapping can reuse them. Artifacts are homogeneous by target and mapping identity; a file containing several record types may produce several such groups. Complete event coverage must equal the accepted input set with no duplicated or missing event key.

A source-record commitment uses a separate versioned domain tag, `u64` count and ordered length-prefixed tuples of source hash, ordinal, optional real offset and canonical source-record digest. Timestamp and exact original typed fields are inside the record digest. Order by source hash and ordinal for this input-set commitment; physical event ordering continues to use the existing stable timestamp/source/offset comparator.

The mapping catalog and native manifest/definition snapshots must be available to the verifier. Case ingestion signs a reference to the installed global-operation content; exports carry the necessary content and signature/trust material rather than depending on the originating machine's global database. Mapping identity, selected input and output must all agree. A self-reported Parquet footer cannot establish the binding.

V3 artifact identity must distinguish canonical envelope commitments from file-byte hashes. Two mapping versions can produce identical Parquet bytes but are different derivations. A generated derivation hash in the artifact path and a V3 lineage key prevent overwriting or conflating them. Derive that path hash from the frozen input/profile, physical schema, partition and part ordinal before serializing the final envelope; it must not depend on its own path or envelope hash. The artifact identity then hashes the complete canonical envelope, including that path and the file-byte hash. File SHA-256 still authenticates every Parquet read. Historical V1/V2 catalog keys remain unchanged.

The generic **seal-inventory V2 encoding can remain unchanged**: it already commits to artifact paths and complete canonical artifact payloads. Its updated coverage logic must include every V3/cache artifact; the final signed chain also binds mapping/decoding/remap events. Recompute inventory counts and hashes from the complete chain, never accept the commitment alone. Add golden tests proving the old seal challenges stay identical.

Recommend an explicit **export V6** capability for V3 artifacts and mapping/decoding snapshots, rather than teaching an old V5 reader to ignore new custody records. Reuse streaming, hash authentication and bounded range-reading code from #205. V5 remains unchanged for old cases. Keep the 1 MiB metadata-frame limit and existing bounded payload streaming; no larger frame is authorized by this design. New envelope/event/export golden bytes and tamper tests require review before implementation/merge.

A separate mandatory `MappingBindingV1` beside an unchanged V2 envelope is a possible alternative, but not recommended: every reader would have to enforce one-to-one binding and complete export coverage while old readers recognize only the artifact. A dedicated V3 discriminator gives a clearer fail-closed compatibility boundary.

Full reproducibility verification regenerates decoded records with the signed parser/format context, applies the exact signed mapping to the exact target, and reproduces artifact bytes with the signed builder/partition policy. Hash/signature authentication without originals or an implementation is a weaker, explicitly reported check; it cannot be labelled successful full reconstruction. Never run downloaded native mapping code during verification.

## 6. Historical cases and narrow remap

### Preserve today's output

Retain the current published parser+legacy-normalizer implementations for their historical signed identities. Refactoring shared decoding must pass byte-for-byte legacy GraphRecord/Parquet golden and reconstruction tests. Published parser versions must not silently acquire new common semantics. Already retired pre-0.1.6 readers do not become supported by this proposal; their existing warnings and re-ingest guidance stay in place.

The new raw-source API is separate and explicitly versioned. A parser without that capability keeps its published legacy route and reports no new-source-contract coverage; it is never adapted by reading normalized JSON. On the new route, a raw decoder must exist before the unmapped constructor can run. Adding it may share framing code, but cannot reconstruct a SourceRecord by reparsing the lossy normalized `GraphRecord.text`. Source-contract/framing changes get a new decoder identity; mapping-only changes do not. Opening a case never reclassifies it.

### Cache decoded records or reread originals?

Recommend an **optional decoded-record cache, off by default**, especially useful for version-pinned cloud objects. Offer it per case/ingestion with a signed choice, a visible disk estimate and explicit analyst confirmation. It is additional local evidence-derived content, not an original-byte copy and not a substitute for the original source manifest. It may contain sensitive original fields; use the same private permissions, taint, guard/redaction and retention controls as other case artifacts. Do not enable it silently.

`irmind-source-records-v1` Parquet stores each accepted record once: origin/reference columns, exact time metadata, format discriminators and a canonical typed source-field payload. Retain **all** bounded original fields needed by a future mapping, not just today's common fields or search text. Store provenance once in columns rather than also duplicating it in the payload. Use the existing pinned compression/Arrow/Parquet stack, without new codec dependencies.

The cache has its own signed V3 decoded-stage envelope and source-record-set commitment, independent of a particular common mapping. Mapping-only remap reads that authenticated cache in bounded batches; it does not call the parser, object store or model. Without a cache it rereads the exact originals/version, reruns the pinned decoder and requires the same input commitment. Cloud rereads still need the current Read scope, transfer budget and explicit acquisition path. Sealed cases retain the current offline/retained-original behavior; this proposal does not add post-seal remote re-verification.

Disk estimate for the existing synthetic cloud benchmark:

| Item | Size | Evidence/status |
| --- | ---: | --- |
| Input corpus | 15,685,651,146 bytes | Measured in the [paired matrix](https://github.com/ns2switch/irmind/blob/c7f5beb/docs/development/benchmarks/common-core-sparse-run.json). |
| Current retained V2 Parquet | 8,924,960,490 bytes | Measured baseline, including retained generations; not the proposed cache. |
| Active event `text` column | 729,559,220 compressed bytes | Measured proxy only; it is not a complete decoded-cache measurement. Other reported column totals include repeated entity rows and cannot be copied as one-row-per-record costs. |
| Additional decoded cache | Roughly 1–3 GB for this repetitive synthetic shape | Planning estimate from the text proxy plus original-field/type/reference overhead. Full original fields may make it larger. Not measured and not an acceptance claim. |
| Conservative planning reserve | Another input-sized allocation plus margin, increased when the sample predicts expansion | Capacity planning, not a compression guarantee or an upper bound. Enforce a configured byte quota while writing. |

Measure the actual codec before enabling a default: total/active cache bytes, bytes per accepted record, compression, write time and peak staging, also on less repetitive source data. For 500 GB, even an extra 10–20% is 50–100 GB; the option must show an estimate and available space. Cache-off keeps the original storage option. Cache-on must never switch off silently on a full disk.

Check free space and quotas before staging, write provisional files only inside the case, check cancellation between batches and remove them on cancellation/error. Publish cache, mapping run and derived manifests using the existing atomic signed-batch mechanism and crash reconciliation. Preserve the previous generation until the complete replacement commits.

### RemapCommitV1

Propose a narrow, analyst-signed operation for **open cases**, not the deferred general `CommonEventMigrationV1`:

1. Verify the existing chain, source-record-set commitment and selected input cache/originals. Freeze the active generation and old/new mapping profiles.
2. Keep decoder, source bytes/version, accepted record identities, timestamps and input digest unchanged. The target schema and identity-normalization policy also stay fixed in the first RemapV1.
3. Prepare new artifacts by applying the new mapping to the same complete input. Keep canonical identities stable: a mapper cannot rename/reuse an existing entity key under a different meaning. It may add role-bearing observations where none existed; original event/record IDs never change. A change of identity policy or target schema requires a separately reviewed operation or a new case.
4. Require exactly the same event-key set and input commitment. Bind old/new mapping identities, old/new complete output-set commitments, counts and the previous active-generation hash in `RemapCommitV1`. Role-free compatibility search projections retain their existing identity meaning.
5. Commit signed replacement metadata and activation atomically; keep all historical artifacts. Cancellation, crash or an intervening case change leaves the old generation active.

This changes interpretation, not the source records. Full verification still needs to replay the decoder against originals to substantiate the cached decoding; a cache-only remap authenticates its signed input and is **not** a fresh full-original verification.

Historical cases without a signed source-record set are not silently eligible. A limited adoption may be prepared only when the exact available historical decoder can reproduce the old generation and a full comparison proves identical record keys, timestamps, counts and provenance. Sign that decoding snapshot before remap. If that proof is unavailable, use a new case with verified originals. No lossy normalized-text reconstruction, automatic precision migration or resurrection of a retired parser is permitted. General cross-schema/entity-identity migration remains deferred.

## 7. Connectors use the same boundary

`siem-elastic` supplies bounded original ECS documents, their index/document identifiers and the authenticated response source reference. `siem-chronicle` supplies bounded original UDM records, their native identifiers and response provenance. They implement acquisition plus a SourceDecoder adapter and use the same mapping registry; neither connector writes CommonEvent directly.

Response evidence is hashed and retained under existing custody rules before its records are published. The mapper cannot query the service, recover credentials or trust configured account/host values as event fields. Acquisition metadata remains separate from reported event data. Structured queries, fixed allowed indices/sources, scope ceilings, TLS/custom-CA checks, time/result/response limits and cancellation are unchanged. No JWT dependency or new credential is introduced by this design.

## 8. Ports, modules and the revised delivery sequence

Proposed ports are synchronous local contracts. Async use cases invoke them through the existing blocking-worker boundary. Sketches below describe proposed APIs, not code added to the workspace:

```rust
pub trait SourceDecoder: Send + Sync {
    fn identity(&self) -> ParserIdentity<'_>;
    fn decode_reader(&self, input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>)
        -> Result<ParseReport, AppError>;
}

pub trait SourceMapper: Send + Sync {
    fn manifest(&self) -> &MappingManifest;
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError>;
}
```

`SourceInput` carries the bounded existing handle, logical source, signed hash/context and cancellation token. Add an optional local-file/random-access route with the same case-local spool rules. The pure mapper takes a borrow, not a serialized JSON round trip; `MappingOutput` wraps the checked CommonEvent, bounded diagnostics and any explicitly declared compatibility projection. The orchestrator retains taint around both input and output. A registry/catalog supplies selection, not a second execution path.

An optional `SourceRecordStore` local port provides bounded cache writing/reading and exact signed-set verification. Preparation should extend the existing case-local prepared-publication workflow additively. `AuditLog::append_batch`, remote `execute` methods, Signer and Verifier need no signature change. These new ports and any preparation additions require approval; none are added by this PR.

| Delivery | Revised scope |
| --- | --- |
| Design | Approve this boundary, signed bindings, remap constraints, optional cache and ports before adapting #205. |
| A: core | Reuse #205's domain types/codes, logical codec, three common physical schemas, typed filters, scoped identity queries, sparse peer reader and bounded file-range reader. Replace `parse_common_*` methods/lifting from StreamingEventParser with SourceDecoder -> selected mapping -> validated writer. Add custody/canonical goldens, no-match handling and contracts. No source interpretation stays in a new parser route. |
| A: comparison baseline | Extract the current role-free projections needed by the cloud and journald benchmark into explicitly identified mapping modules, with unchanged search identities and empty common classifications. They are not a hidden parser bridge. Do not run graph benchmarks against an empty unmapped projection. Existing historical parser paths stay frozen. |
| B: high-value semantics | Native mappings for EVTX; Linux auth.log/secure and auditd; CloudTrail; ECS; OCSF; Zeek and Suricata. Cover success/failure/absence, same value in two roles, actor/target separation, namespaces and PID reuse. Mapping versions change independently of decoder versions. |
| C: community mappings | Velociraptor, Hayabusa, Chainsaw, plaso, EZTools, syslog application mappings, journald, nginx and Apache, plus declarative mapping examples. Until present, these have explicit extraction-only/unclassified coverage, not fabricated classifications. |
| Connectors | Elastic ECS and Chronicle UDM after A, using SourceDecoder and separately versioned mapping modules. Credential/JWT review remains separate. |

Reuse the existing common-mapping issues rather than create duplicates: [Velociraptor #194](https://github.com/ns2switch/irmind/issues/194), [Hayabusa #195](https://github.com/ns2switch/irmind/issues/195), [Chainsaw #196](https://github.com/ns2switch/irmind/issues/196), [plaso #197](https://github.com/ns2switch/irmind/issues/197), [EZTools #198](https://github.com/ns2switch/irmind/issues/198), [syslog #199](https://github.com/ns2switch/irmind/issues/199), [journald #200](https://github.com/ns2switch/irmind/issues/200), [nginx #201](https://github.com/ns2switch/irmind/issues/201), [Apache #202](https://github.com/ns2switch/irmind/issues/202) and [declarative #203](https://github.com/ns2switch/irmind/issues/203). Each mapping issue needs `good first issue`, `help wanted` and `area/parser`, with the source-field table, synthetic SourceRecord fixture, exact expected common event and shared contracts as acceptance criteria. Broader generic JSON and cloud-export mapping coverage remains explicit future work, not a claim of automatic classification.

## 9. Performance and approval gates

The extra boundary does not inherently require another parse, full JSON tree, record copy or spool. Decode once into a bounded borrowed view; select from indexed immutable manifests; compile declarative paths/status tables once; map directly through the domain constructors; optionally write the decoded cache alongside the mapped stream. Do not construct a legacy JSON projection merely to parse it back into common fields.

As a planning budget, allow roughly 5–10% for selection/mapping/validation over decoding, and measure cache writing separately; these are estimates, not observed overhead or relaxed thresholds. The earlier common bridge's failed matrix cannot establish the cost of this architecture. The optional full decoded cache may have a larger cost and must be measured with its actual all-field codec.

After design approval and adaptation, measure optimized release builds on the same runner class: three >=1 GiB repetitions per representative source; one complete 15 GB cloud/endpoint matrix with 1, 64, 1,024 and 1,025 hosts, chronological and disordered; cache off/on reported separately. Record decoding, selection/mapping, hashing, staging, Parquet and custody time, disk and query p50/p95. Timers must identify overlap and include both successful and failed samples. Repeat deterministic HuntEval/needle checks with private answers isolated from every decoder, mapper, tool and model.

Keep **900 seconds** for cloud/chronological and **1,350 seconds** for stress, with the existing query deadlines, sample/hop/expansion/token limits, rollback and hash verification. No mode becomes a default by passing a smaller corpus or disabling a check. Check mixed-target coverage and duplicate-event suppression as well as speed.

The design approval must explicitly cover: new SourceDecoder/SourceMapper/cache ports; the application-level compatibility projection boundary; V3 envelope and the acyclic signed decoding/profile/receipt records; export V6 and unchanged historical seal bytes; the narrow remap/adoption constraints; and the optional full decoded cache. Implementation, new golden bytes, native mappings and performance changes follow separately. #205 remains a draft until that review.
