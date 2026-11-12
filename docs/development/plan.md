# IRMind reference plan

This internal plan records historical acceptance criteria and decisions behind the first pre-releases. Future sequence and ownership follow the [public roadmap](roadmap.md); this document does not set future release dates or assign the unattended gateway to this repository. The English version is authoritative.

## Skills in 0.4

The approved [installation contract](skills-installation-contract.md) and [case/export contract](skills-case-format-contract.md) govern the implementation. Local compilation and storage are separate ports. The agent receives only active names and descriptions until a bounded, policy-checked load. Analyst-pinned snapshots and Agent-signed load receipts remain methodology, never evidence. Export V7 includes referenced installation admissions; the export port is named `export_case`, independently of the file version. Windows triage, Linux triage and AWS credential compromise must pass scripted synthetic ingestion → method load → investigation → confirmed finding → sealed/offline-verified export before the release. No provider is enabled by default.

## Current pre-1.0 delivery order

The [pre-1.0 format decision](decisions.md#pre-10-format-policy) supersedes compatibility and V2-comparison requirements in the historical sections below. Minor versions may change formats without migrations until stabilization, expected around v0.6–v0.7. Preserve the creating executable for old cases, or re-ingest verified originals into a new case. Decide parser retention and stable compatibility before 1.0.

1. Publish the policy and an explicit format-impact note for each release.
2. Implement approved `omit_text` in the current table interpreter and continue phase B source families and the Windows/Linux/CloudTrail authentication-failure contract.
3. Add format-only SourceDecoders and extraction-preserving mappings to every remaining parser before removing its legacy route. Preserve current search identities and unclassified events where no semantic mapping exists.
4. Reject foreign-version cases/exports before work; disable unavailable definition interpreters with visible startup warnings.
5. Make mapped V3 the only CLI/TUI/demo writer. Remove relative V2 gates and track the 1,025-host stress miss separately; keep absolute ingestion and ordinary-query deadline checks.
6. Use separate PRs for retired formats, dead code/test helpers, dependency/features cleanup across all three workspaces, and repository/CI/design cleanup. Keep current goldens, security tests, fuzzing and dependency-direction checks. Report deleted lines/tests/dependencies, binary size and CI time per PR.
7. Complete experimental Elastic and Chronicle mappings/connectors, then prepare v0.3.0 with the breaking-format notice, signed assets, attestations, SBOMs and verified installers. Publish v0.3.0 from green main after signed distribution and clean-installer verification; the analyst has authorized its tag.

Decoder rollout: JSON, declarative definitions, ECS, OCSF, DFIR formats, syslog, Linux inputs, EVTX, Zeek and Suricata have original-field decoders and identified semantic or extraction-preserving mappings. The cross-source authentication-failure contract covers Windows, Linux and CloudTrail. Use that complete catalog for the sole-writer change; missing decoders fail closed.

Finish multicore ingestion before retiring the old writer. Worker counts follow available CPUs and a global memory budget; canonical append and eviction remain sequential, while independent partition completion runs concurrently. Ordered sources use bounded queues, and disordered sources use private case-local spools. Keep the current constructor and physical goldens. Validate identical signed output at different worker counts and the release 15 GB absolute targets before integrating the sole-writer change.

The multicore release measurements are recorded in
[benchmarks](benchmarks.md#record-workers-in-a-single-source) and
[the complete mapped matrix](benchmarks.md#complete-mapped-matrix-with-parallel-independent-source-sorts).
Current-format tests compare complete artifact inventories and signed chains at
worker caps 1, 2, 4 and the available-machine cap. Native decoder contracts also
compare canonical source bytes, including provenance, across those settings.
The isolated EVTX helper uses bounded standard-library chunk workers, with
native containment and byte-identical output contracts on Linux, macOS and
Windows. The combined mapping/helper benchmark records single-file measurements
on four-core Linux/Windows runners and a five-core macOS runner. Windows keeps
one verified network witness per session and canonical serial source starts.
The obsolete buffered parser and graph-construction contracts are removed;
current queries and signed artifact verification remain unchanged.

No old case migrates automatically. No model or connector becomes enabled by default. Obsolete compatibility controls can be removed only with their retired paths; retained-version security guarantees and limits stay unchanged.

The following milestone history records earlier deliveries; compatibility commitments and V2 activation comparisons there do not govern current development.

## Principles

1. The model proposes; domain policy decides. No remote port executes without `AuthorizedCall`.
2. Read is the default. Enrich needs signed analyst approval; Contain is denied.
3. Every custody event enters an append-only, hash-chained, Ed25519-signed audit log.
4. Original evidence stays intact. Model input is guarded, redacted, bounded, and marked as untrusted.
5. Policy, audit, signing, guard, or redaction failure stops the operation.
6. The composition root reads credentials only through the explicitly selected secret backend and injects them into connectors. Modules never read them from the environment, log them, or send them to the model.
7. `irmind-security` is mandatory. External values carry `Tainted<T>` provenance.
8. Each product implements a port in its own crate; adding one does not change the core.
9. Dependencies point inward: domain ← application ← adapters / security / TUI ← binary. CI checks this direction.
10. macOS, Linux, and Windows must preserve the same security guarantees.
11. The TUI is the analyst's main workspace. `irmind` with no subcommand opens it; CLI subcommands reuse application use cases for automation.

## Milestones and acceptance criteria

The agent loop keeps case context separate from the analyst's message. Provider-native tool-call IDs and guarded tool results stay linked across rounds. The signed case log supplies prior analyst prompts and screened final replies. The policy sets a default of 25 model rounds per turn (maximum 100); a limit produces a final no-tool summary and `/continue` rather than discarding prior work. Older conversation may be compacted into a guarded, signed summary while recent turns and confirmed findings remain available.

| Milestone | Scope | Done when |
| --- | --- | --- |
| H0 Skeleton | Workspace, lints, CI, cargo-deny, dependency-direction test. | The test rejects an intentionally introduced reverse dependency. |
| H1 Domain | Typed IDs, risk and approval types, execution mode, actors, taint, scoped policy and quotas, case entities, pure hash-chain rules. | Tests cover every policy rule and chain failure. |
| H2 Application | Cancelable async remote ports; synchronous local ports through `spawn_blocking` in async use cases; investigation, approval, reporting, seal, verify, ingest, export, and export verification; generic module dispatch and port contracts. | No local operation blocks the runtime; each remote family has an approved-call end-to-end test; no raw data reaches the fake LLM. |
| H3 Security | Nonce isolation, normalization, injection detection, taint containment, safe output, startup corpus self-test, signed detection event. | An obedient fake LLM cannot execute an unapproved call; a broken rule blocks startup. |
| H4 Signed storage | SQLite WAL, distinct Analyst and Agent keys in an explicitly selected OS or encrypted-file backend, signed source manifests with SHA-256 and optional original copies, verify, seal, export, expected-key verification. | Verification detects database tampering and reports missing or changed originals; a sampled check states its limited coverage. Legacy copied cases still verify. |
| H5 LLM | Streaming tool calls, case-state context, per-case token and cost limits. | Recorded-response tests and a documented manual test pass. |
| H6 TUI | Home case list and creation; chronological conversation with multiline input, scroll, command completion, optional case sidebar, and cards for calls and findings; cancelable work, first-run guide, module status, scope and evidence commands. | `ratatui::TestBackend` covers navigation, completion, cards, and a full case from creation through export without the CLI. |
| H7 Graph | Streaming custody manifests and partitioned Parquet for 15–500 GB investigations; Arrow and Parquet scan signed, hash-checked IRMind artifacts with bounded term and graph queries. CloudTrail, GCP Cloud Audit Logs, Azure Activity and Entra ID sign-in logs, and generic JSON have streaming parsers. | Existing cases migrate without breaking verification; a standard runner converts 15 GB in under 15 minutes and query p95 stays under 10 seconds, with 1 GB and 15 GB phase profiles. |
| H8 Integrations | Cloud, SIEM, EDR, and threat-intelligence modules passing shared port contracts; S3, GCS, and Azure Blob object storage are Read-only ingestion sources. | Each module has recorded-response tests and a setup guide; the three object backends pass a shared streaming contract and enforce case scope. |

H7 is **done**. The [standard-runner benchmark](https://github.com/ns2switch/irmind/actions/runs/40776509647) converted the synthetic 15 GB corpus in 216.761 seconds, kept measured query p95 below 10 seconds, and recorded the 1 GB profile. Migration, source verification, and graph verification have automated tests. This milestone covers local Parquet storage; cloud object reads remain H8 work.

## Historical 0.1.0 scope

This section records the pre-release scope; it is not a schedule for future work.

New experimental log formats use one Cargo crate per parser. The parser registry probes at most 64 KiB per source, chooses only a unique high-confidence match automatically, asks the analyst on ambiguity, and refuses unattended selection. Parser identity, version, confidence, and selection mode are signed in `SourceManifestV2`; historical V1 manifests remain verifiable. A source-specific rebuild uses the signed parser version. Line-delimited formats count rejected records and keep at most three bounded untrusted excerpts. A malformed monolithic JSON array cannot be safely resynchronized, so its file is rejected while other case evidence remains intact.

The MVP includes P: signed source manifests, optional original copies, partitioned Parquet, bounded direct queries over signed Parquet, the four streaming source parsers, representative 1 GB and 15 GB benchmarks, and verified migration of existing cases. It also includes R: read-only S3, GCS, and Azure Blob ingestion with explicit credentials, signed case scope v3 for bucket/container prefixes, transfer budgets, a prior signed listing, one streamed download to a private temporary spool, and a shared streaming contract. Existing v1/v2 scopes and signed audit, seal, and export layouts remain unchanged. C5 (SIEM alert retrieval and tracing), C6 (structured SIEM queries), and the existing H8 module contracts remain in scope. [Cloud query engines](cloud-query-design.md) are designed now but implemented after the MVP.

The 0.1.0 scope included GCP and Azure only as object-storage read sources and exported-log parsers. That historical roadmap placed Chronicle with the v0.2 connectors and source-side queries in v0.5. The current roadmap places the experimental SIEM connectors in v0.3, and source-side queries and remote re-verification in v0.6, and the unattended gateway and watches in another repository after the engine API. A signed repeat read rechecks a remote original while a case is open; a sealed case can verify an explicitly retained copy offline.

For uncopied originals, the signed manifest proves what IRMind observed when it hashed each source, while later full verification requires access to that same source. Sampling verifies only selected originals. Neither mode claims that an unavailable source remains intact. Export without originals is verifiable as a signed manifest and case chain, not as a complete portable evidence package.

The original MVP exit criteria remain: H0–H8 meet their stated acceptance criteria, the H5 manual test is documented, at least one connector has been tested against a real test environment, and the release has a changelog and downloadable binaries. Synthetic recordings alone do not satisfy the connector test. `v0.1.0` was published as a pre-release before the two manual validations. H5 has since been closed by analyst decision after a real DeepSeek greeting test, as recorded in [manual validation](manual-validation.md#result-record). The live-connector gate remains open. Unreported H5 procedure steps remain pending analyst records; the tag itself does not satisfy any validation gate.

| MVP exit criterion | Status | Evidence or next action |
| --- | --- | --- |
| H0–H4 and H6 automated acceptance | Done | Workspace gates, signed custody, policy and TUI tests run in CI. |
| H7 local Parquet and benchmark acceptance | Done | [15 GB runner benchmark](https://github.com/ns2switch/irmind/actions/runs/40776509647) and migration tests. |
| H8 existing connector and object-source contracts | Done | Recorded synthetic contract suites and setup guides. |
| H5 recorded-response tests | Done | CI contract and application tests. |
| H5 conversation-loop correction | Done | PR #31 integrated with the trusted-system-role security correction; no manual DeepSeek test was run before merge. The later analyst acceptance is recorded below. |
| H5 manual test with real DeepSeek | Recorded | IRMind 0.1.2 answered a greeting naturally without unnecessary tool calls. Other manual observations remain unrecorded. See the [public compatibility summary](manual-validation.md#result-record); detailed validation records remain private. |
| One connector against a real test environment | Pending analyst | Run the Splunk lab procedure in [manual validation](manual-validation.md) and record the result. |
| Release dry run without a tag | Done | [Manual CI run 41117075395](https://github.com/ns2switch/irmind/actions/runs/41117075395) passed on Linux, macOS and Windows before the first tag. |
| `v0.1.0` and `v0.1.1` tags, changelog and downloadable binaries | Done with explicit validation exception | Both pre-releases were published from green `main`; v0.1.1 adds signed and attested assets. These releases preceded H5 acceptance; the live-connector gate remains pending. |

## Historical 0.1.0 release process

The 0.1.0 release used unsigned, checksummed binaries. The 0.1.1 release added keyless Sigstore bundles, GitHub attestations, an SBOM, and verified installers. Both were published with an explicit exception for the pending manual model and live-connector checks. Do not treat a synthetic connector recording as the analyst's live test; record those checks in [manual validation](manual-validation.md) and fix any discovered defects in 0.1.x. The [public roadmap](roadmap.md) governs future work.

## Gateway compatibility for a separate repository

This repository does not implement the unattended gateway or watches. Preserve distinct Analyst and Agent signing keys, `ExecutionMode`, unattended scoped reads only, analyst-signed approvals, and service-safe concurrent use cases so a separate project can use the engine API.

## Accepted design choices

- `ProposedCall` has no risk field. `Tool` determines risk.
- The derived graph is queried directly from signed Parquet artifacts.
- Parquet is the derived local event store for large cases; Arrow reads only signed IRMind-produced artifacts. Original copies are an explicit option rather than an implicit requirement. Versioned source and artifact records and streaming v4 export extend custody; the existing signed entry encoding and v3 export remain valid.
- `Actor` names the signer; event origin is separate.
- No LLM is enabled by default. Use only synthetic data until provider compliance approval.
- Local Ollama may use keyless loopback HTTP or HTTPS; remote models require HTTPS.
- Signing and secret backends are selected independently as `os` or `file`. There is no silent fallback; a missing selected backend fails closed.
- An encrypted file with Argon2id and XChaCha20-Poly1305 permits use over SSH without a graphical keyring. Migration preserves the analyst fingerprint and adds a signed global operational entry, even without a case.
- Shared permission and durable-write helpers live in `irmind-fs`; production adapters cannot depend on one another.
- New signed configuration changes carry the complete canonical non-secret configuration. Startup requires explicit restoration or reviewed acceptance when the file differs; CLI automation fails closed.
- Effective egress overrides from flags or the environment are shown and signed before a TUI session, or signed before CLI automation runs. Rejection uses saved settings.
- Rustls uses native roots; its platform-verification limits remain documented.

## Distribution

The v0.1.0 pre-release has unsigned binaries and `SHA256SUMS`. From v0.1.1, release tags publish binaries and a checksum list signed with keyless Sigstore, plus GitHub build attestations and an attested SPDX SBOM. Relevant nightly runs build test artifacts but do not publish a release. Pull requests and merges to `main` run development checks without release builds. Apple notarization and Windows Authenticode remain deferred.

## Documentation

English is authoritative. Public guides live under `docs/`; Spanish user guides identify the English source commit. Do not translate or alter signed event identifiers, canonical formats, or the bilingual attack corpus merely to localize documentation.

## Declarative parser block

The experimental `parser-declarative` module is integrated through [PR #151](https://github.com/ns2switch/irmind/pull/151) behind a default Cargo feature. Definitions are strict, bounded TOML, compiled only from approved bytes, with low-confidence detection requiring analyst selection. New additive parser identity methods borrow dynamic names/versions; catalog keys own their strings. Native parser methods keep their defaults. Signed `SourceManifestV2` and `ParquetArtifactV1` tags and encodings remain unchanged: the existing parser-version field contains the definition SHA-256. Install/change/deactivate/restore use the current signed global operational envelope and private atomic storage. Historical resolution uses verified signed snapshots. The additive contracts are integrated; the artifact-v2 design is recorded in #143; its implementation follows JSON-order independence and syslog/Linux.

## Approved timestamp precision design

[Parquet artifact V2](parquet-artifact-v2-design.md) addresses [issue #143](https://github.com/ns2switch/irmind/issues/143): precise UTC instants, stable equal-time ordering, compatible reads and explicit verified migration. The design includes generic bounded scope partitions and signed overflow. The selected default is 64 ordinary host values per case, with an immutable ceiling of 1,024 and signed overflow. Implement only after JSON-order independence and syslog/Linux are complete, in separate PRs for types/envelope and golden bytes, mixed V1/V2 writes/reads, partitions, migration, export v5 and benchmarks. Design changes require a separate compatibility review. Existing parsers must retain full source timestamps while the current derived index remains second precision.

Generic partition preparation (step (c)) is implemented in [PR #170](https://github.com/ns2switch/irmind/pull/170): parser-owned closed profiles, signed deterministic caps/overflow, case-local bounded staging and stable ordering, hash-derived paths and checked host filters. The [release audit](json-line-order-compatibility.md) confirms lexical `json-stream-v2` compatibility for published tags through v0.1.5; development insertion-order cases are unsupported. The initial rollout kept default TUI writing at V1 until migration/export V5 and the release benchmarks were integrated. The current selection and measured gate are recorded below.

## Approved parser and precision work order

1. Make signed, hashed and reconstructed output independent of `serde_json::Map` order; test unchanged golden bytes with `preserve_order` enabled. A changed existing golden requires analyst review.
2. Deliver separate syslog and Linux modules, retaining explicit/inferred timestamp context. Use reviewed `flate2` for bounded gzip; Linux adds no new dependencies.
3. Implement the approved artifact-v2 design in the separate PRs listed above.
4. Add EVTX through an isolated `irmind-evtx` helper in its own Cargo workspace, using official upstream `evtx` without a fork. Its features must not unify with the main workspace. The helper has no network or shell, fixed arguments, bounded runtime/output and untrusted NDJSON with source provenance. Rejection is atomic; unavailable helpers remain visible as unavailable. Include signed release/install assets, attestations, SBOM and an unsafe report. Run malformed-input fuzzing for at least one hour and nightly. Dependency and distribution changes require a separate compatibility review.

## Native syslog parser

The experimental feature-gated `parser-syslog` uses the shared detection registry and existing SourceManifestV2. RFC 5424 retains source precision; RFC 3164 binds explicit year and fixed offset into the signed inference context and parser version. Bounded gzip uses the reviewed, documented `flate2` dependency. Synthetic contracts, signed ingestion/reconstruction, unchanged-format goldens, fuzzing and local throughput measurements are documented in [the parser contract](syslog-parser.md) and [benchmarks](benchmarks.md). Linux was delivered separately; artifact-V2 implementation follows the sequence below.

### Per-ingestion RFC 3164 time correction

[PR #162](https://github.com/ns2switch/irmind/pull/162) implements the approved optional LogParser time-context capabilities. New syslog sources bind a typed first year, fixed UTC offset, visible December/January rollover and confirmed basis in existing SourceManifestV2 fields and parser version. New ingestion never reads a global year or machine time. Historical v1 sources retain exact reconstruction. Linux authentication parsing reuses this flow in its own follow-up PR. EVTX remains an isolated helper after artifact V2; the superseded in-process proposal #153 is closed.

### Linux exports before artifact V2

The independent parser-linux crate extends the detection registry without external dependencies. It reuses the approved per-ingestion context and shared pure calendar with syslog; neither parser depends on the other. Auth/secure, bounded audit correlation, journald microsecond originals and common/combined HTTP exports are experimental and tested with synthetic episodes only. Artifact V1 remains second precision until the approved V2 implementation. Existing signed encodings and parser versions outside syslog/Linux remain unchanged.

### Automatic community presentation

Priority before artifact V2: deliver global card expansion and its `/expand` fallback in v0.1.4, then the isolated ten-scene live presentation in v0.1.5. Its versioned script drives the same parser registry, signed ingestion, approvals and custody as ordinary commands. No new application port, signed format, dependency or remote provider is introduced. PTYs cover automatic/manual playback and cleanup on Linux, macOS and Windows; native GUI/SSH/tmux keymaps remain separately reported manual checks.

### Standard-size demo and artifact-V2 implementation order

The demo must support 80 × 24; 100 × 40 is recommended. Compact narration scrolls with fixed controls, and secondary panels hide at small sizes. Publish this adjustment before the artifact-V2 implementation, without a separate release.

Implement the [approved artifact-V2 design](parquet-artifact-v2-design.md) in separate PRs: checked instant/precision types and signed envelope/goldens; V2 writes and mixed reads with one stable comparator; generic bounded partitions; explicit open-case migration and export V5; release-mode 15 GB cloud and endpoint/network cardinality benchmarks. Start the host cap at 64 and retain 1,024 as the hard ceiling. Stop before a merge if implementation would depart from the approved design. The isolated EVTX helper, Elastic and Chronicle follow this work.

### Artifact V2 implementation evidence

The first implementation PR defines checked instants/precision, the additive signed envelope and [canonical golden layout](parquet-artifact-v2-wire.md). Default CLI/TUI writes remain V1 while the mixed reader/writer, generic allocator and export V5 land in separate PRs. The separate partition, migration/export and release-benchmark workstreams below record their compatibility gates. The approved operational default is 64 ordinary hosts; the optimization acceptance section below retains the activation gates and the 1,024 hard ceiling.


Step (b), [PR #168](https://github.com/ns2switch/irmind/pull/168), implements the [approved storage/parser contracts](parquet-v2-port-transition.md), an explicit precise writer, mixed-schema queries, reproducible compatible compaction and native precision projections without changing V1 goldens. Production activation waits for generic partitions and V5 export; this prevents an intermediate rollout from blocking ordinary case export. Step (c) is integrated below. Explicit migration/export and release-profile benchmarks remain activation gates.


Step (c) is integrated in [PR #170](https://github.com/ns2switch/irmind/pull/170). Source-bound profile routing, deterministic allocation, Unicode-policy pinning, bounded case-local staging and host filters are implemented. Default writing remains V1 until migration/export V5 and the release benchmarks integrate; release-scale partition benchmarks remain separate.

### Explicit migration and export V5

[PR #172](https://github.com/ns2switch/irmind/pull/172) implements attended open-case migration and V5 export through shared application cases of use. Historical V1 envelopes, source manifests and seal challenges retain their encodings. Preparation verifies originals and old/new reconstruction before one atomic signed replacement batch. A shared lineage interpreter serves application checks, queries and export verification. See [migration guidance](case-migration.md) and [bounded wire commitments](parquet-v2-migration-contracts.md#bounded-canonical-migration-record). The initial rollout retained V1 until migration/export and the release benchmarks were integrated. See the current interactive selection below. EVTX and experimental SIEM connectors follow those steps.


### Current parser reconstruction boundary

New ingestions use the current reader identities, including `json-stream-v3`. Retired parser implementations are not shipped. Existing signed formats remain readable and authenticatable; regenerating an older reader's records requires a new case with verified originals. See [the reader decision](decisions.md#current-parser-identities-and-reconstruction). The release-profile benchmark remains separate from reader correctness changes.

### Informational warnings for retired readers

Case opening and verification warn about the affected retired JSON, ECS, OCSF, DFIR and declarative readers from v0.1.1–v0.1.5. An authenticated original size at or below 4 MiB suppresses the warning; missing size remains conservative. The TUI displays a guarded, unfolded warning, and CLI verification writes it to stderr without changing a valid result or signed history. Guidance links to the published changelog and creating a fresh case from verified originals. No release is created only for this notice.

The [proposed parser retention policy](decisions.md#parser-retention-policy-for-10-pending-confirmation) is a [1.0 criterion](roadmap.md#10-criteria), pending confirmation before that release.

### Artifact V2 release benchmark

Step (e) compares release-mode V1/V2 CloudTrail ingestion and queries at 1 GB and 15 GB, plus 15 GB endpoint corpora with 1, 64, 1,024 and 1,025 hosts. It records normalized staging disk peaks, signed partition/file counts, compressed column sizes and filtered/unfiltered latency. The [measured recommendation](benchmarks.md#host-cap-recommendation-and-remaining-gate) retains 64 hosts as a conservative initial cap, with a hard ceiling of 1,024. It does not establish an optimal cap because the run holds that cap fixed while varying source cardinality.

The initial profiled run exceeded the 900-second V2 ingestion target and the unfiltered endpoint timeline deadline, so it retained V1 as the default. Later paired optimization results and the current interactive selection are recorded below. The analyst subsequently approved a separate disordered stress gate, as recorded below.


### V2 optimization acceptance

This records the historical optimization gate. The analyst-approved release/stress distinction in the current selection and step (e) closure below supersedes its disordered-ingestion threshold.

The ordinary-host default is approved at **64 per case**, with an immutable ceiling of **1,024** and signed overflow. This is the selected operational default, not a claim that a fixed-cap cardinality experiment proved an optimum.

Before activation, optimize ordered-source writing, bounded natural-run merges, authenticated file/row-group timeline pruning and cloud entity lookup in separate changes. Measure the release baseline and candidate in the same runner, with cloud and separate chronological/disordered endpoint corpora at 15 GB and 1, 64, 1,024 and 1,025 hosts. Preserve the 900-second ingestion target for both endpoint corpora and all existing query targets. A disordered-corpus miss must be reported rather than changing its target. V2 remains disabled until the cloud and chronological acceptance targets pass.

[Event-reference co-observations](coobservation-reference-proposal.md) are an evaluation only. Any change to the signed schema requires its own decision before implementation.

### Current V2 selection for CLI, TUI and demo

The [final paired release candidate](benchmarks.md#final-v2-ingestion-and-query-gate) meets the existing cloud and chronological activation gate: 15 GB cloud ingestion takes 865.973 seconds; chronological endpoint ingestion takes 488.131–561.596 seconds at 1, 64, 1,024 and 1,025 hosts. All sampled candidate queries, including ordinary and overflow filters, have zero errors and p95 below 4.7 seconds. The complete release matrices retain before/after data from the same runner for each pair; separate runner instances are not interchangeable speedup baselines.

CLI, TUI and offline-demo sessions now select the existing V2 writer. Opening an existing V1 case does not migrate its artifacts or change signed history. New sources can coexist with V1 sources; replacing an indexed source's artifact version still requires explicit migration. Existing application export selects V5 whenever the signed case contains precise artifacts or a migration record. CLI automation now selects the same V2 writer as the TUI and demo; migration of historical sources remains explicit.

The four disordered controls take 1,007.507–1,120.179 seconds and meet the analyst-approved 1,350-second stress gate. The cloud and chronological release gate remains 900 seconds, with unchanged query targets. This supersedes the former disordered gate; further stress optimization is after v0.2.0. Measure split/merge/copy/replay separately and evaluate a bounded merge feeding the provisional writer directly, with unchanged source/run authentication, ordering, allocation, cancellation and rollback. No smaller corpus replaces either workload; query deadlines and custody checks stay unchanged.

The event-reference co-observation proposal remains a design evaluation. Its measured payload budget is not an implemented disk saving. Changing its signed schema requires a separate compatibility decision and new goldens.


### Step (e) closure and v0.2.0 sequence

The [analyst-approved acceptance decision](decisions.md#analyst-approved-release-and-disordered-stress-gates) closes step (e): cloud and chronological ingestion remain below 900 seconds; disordered stress ingestion remains below 1,350 seconds; query targets are unchanged. Keep the 64 ordinary-host default and 1,024 hard ceiling. Co-observation references, cloud `co_entities` disk reduction and direct merge-to-writer optimization are after v0.2.0.

Next, implement EVTX as an isolated official decoder helper and request dependency/distribution review before merging. Then implement experimental Elastic and Chronicle connectors, requesting review before introducing JWT dependencies or new credentials. Prepare v0.2.0 with a complete changelog, optional V1→V2 migration guidance and the existing signatures, attestations, SBOM and verified installers. Opening a case never performs an implicit migration.

## Current release and common-schema sequence

The [public roadmap](roadmap.md) defines the current order; earlier milestone and phase notes are historical where they differ. Finish the restored Zeek/Suricata modules and publish v0.2.0 with artifact V2, optional explicit precision migration, export V5 and the isolated EVTX helper. No schema-common implementation or new SIEM connector is part of that release.

For v0.3, implement the [common event schema](https://github.com/ns2switch/irmind/blob/6dfa5ef620f044892dbf1cfac9f27d5ffed22bbb/docs/development/common-event-schema.md) in separate core and mapping changes. The core covers types, fixed codes, physical schemas, writer/readers, bounded typed filters and verify/export; the approved SourceDecoder → frozen SourceMapper pipeline produces V3 artifacts and export V6. No interpretation is added to parsers. A source with no mapping is explicitly unclassified; all current parsers provide a raw decoder; there is no historical ingestion route. Review the core before merging it. Initial mappings cover EVTX, Linux authentication/auditd, CloudTrail, ECS, OCSF, Zeek and Suricata. Community issues cover remaining mappings. Elastic and Chronicle follow the core and still require credential/dependency review.

CommonEventMigrationV1 is deferred: existing cases remain readable, with no automatic semantic migration. Re-ingest verified originals into a new case when new classifications are needed. Benchmark 1 GiB representative sources three times and the complete 15 GB matrix once, in release builds on the same runner class. Keep current targets.

Skills move to v0.4, subagents to v0.5, public launch follows subagents, source-side queries move to v0.6 and detection/reports/engine API to v0.7.

## v0.2.0 release scope

The release includes precise artifact V2 in the CLI/TUI/demo, optional explicit V1 precision migration, mixed-generation export V5, isolated EVTX and the restored experimental Zeek/Suricata modules. It does not include Elastic, Chronicle or the new common event schemas. Existing cases stay readable and never migrate on open. Semantic migration remains deferred; re-ingestion into a new case is available.

Keep the evaluation-only warning: H5 is accepted by analyst decision after the recorded DeepSeek greeting, while the remaining procedure observations and a real-connector validation are still pending. Signed release assets use the existing tag workflow with main/helper SBOMs, Sigstore, provenance and clean installer checks. Native signing/notarization and the recorded post-release performance work remain separate.


## Mapped artifacts and physical compaction

**Historical activation sequence, superseded by the sole-V3 pre-1.0 decision.** The [source/mapping design](source-mapping-design.md) and [layout contract](mapped-artifact-layout.md) govern the experimental v0.3 core integrated in [PR #205](https://github.com/ns2switch/irmind/pull/205). Preserve source sets, profiles, mapping receipts and retained parent files. Layout compaction changes only physical grouping, with its own signed receipt and no change to historical custody formats or seal bytes. The core remains opt-in; default activation requires its own golden and release-performance review. Record inactive-parent bytes and their share of the retained case in every 15 GB scenario. If their size exceeds roughly 20% of active artifacts, design signed retirement separately; do not delete them in the core change.

The [complete mapped-pipeline release measurements](benchmarks.md#source-decoding-mapped-v3-and-retained-layout-parents) record the pre-direct implementation's ingestion and dense entity-query misses. Integration of the experimental core does not satisfy the activation gate; default CLI/TUI/demo writing stays V2. The [inactive-parent retirement design](mapped-parent-retirement-design.md) is a proposal only, with no file deletion implemented.

**Historical activation sequence, superseded by the sole-V3 pre-1.0 decision.** Common V3 writing, export V6 and ParquetLayoutV1 are explicitly experimental and unstable until default activation, with no promised migration for experimental derived layouts. The optional setting requires a warning, an analyst-signed configuration operation and an ingestion notice. V2 stays the default. Direct final-file writing and dense entity lookup each have their own PR before the separate default-activation change. The [analyst's absolute and paired +10% activation gate](benchmarks.md#analyst-decision-common-writer-default-activation) governs that change; semantic mapping work follows it.

### Common-event source mapping families

**Historical activation sequence, superseded by the sole-V3 pre-1.0 decision.** CloudTrail is the first semantic mapping family: a bundled, hash-pinned declarative definition runs independently of the JSON decoder. Frozen broad compatibility benchmarks keep their previous constructor; the application catalog uses explicit disjoint CloudTrail/generic selectors. V1/V2 custody stays unchanged, and the common writer remains opt-in while its revised activation evidence is evaluated. Windows, Linux, ECS/OCSF and network mapping families follow independently with shared contracts and a cross-source authentication-failure query.
