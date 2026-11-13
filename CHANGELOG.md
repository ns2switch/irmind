# Changelog

This file records user-visible changes. IRMind remains a pre-release for evaluation with synthetic data.

## Unreleased

### Microsoft Entra source coverage

- Add experimental, default native SignInLogs and AuditLogs decoding and
  identified mappings for Azure Monitor resource logs and Log Analytics object
  rows, including non-interactive and service-principal sign-ins.
- Preserve nanosecond time and original dynamic/MFA/Conditional Access fields;
  map explicit outcome and tenant-scoped actor/target roles. Update the Azure
  skill and its complete scripted episode to use native semantic queries.
- Format impact: new parser/mapping identities, with no envelope, schema,
  seal or export framing change.

### Network interpretation

- Classify native Zeek and Suricata records with typed endpoint roles, protocol
  fields, explicit status outcomes and unconfirmed source alerts. Update the
  network skill's synthetic episode to query category, outcome and role.
- Network mapping identities and their current logical golden projections change;
  source decoders, signed envelopes, physical schemas and export format do not.


### GCP Cloud Audit and GKE interpretation

- Add a default, experimental Cloud Audit JSON/NDJSON source decoder and bundled
  service/status mappings, sharing explicit cluster confirmation with GKE.
  Preserve nanosecond time and original fields; distinguish reported caller,
  target resource and source/destination endpoints. Redacted IPs remain unknown.
- Keep missing RPC status unknown and classify project-policy operations only
  from documented exact method names. Validate GKE namespace/resource paths and
  keep zonal locations distinct from regions. Unknown services retain coverage gaps.
- Update the GCP service-account skill and its scripted episode to use native
  IAM/outcome/role filters, with independent evaluator-only HuntEval answers.
- Format impact: no additional envelope, export framing or seal change.

### Kubernetes and Falco source modules

- Add separate experimental native Kubernetes audit and Falco JSON decoders, selected by the bounded detection registry. Original fields, nanosecond timestamps and actual offsets are retained; mappings remain independent.
- Ask for required cluster acquisition context in the TUI, with explicit per-file or batch confirmation. CLI and `/ingest --cluster` use the same typed, signed context. No identity is inferred from the machine or path, and no live API access is added.
- Include hash-pinned Kubernetes and Falco table mappings: explicit API outcomes, actor/impersonation roles, namespaced target resources, and unconfirmed source alerts. Cluster search projects validated fields instead of whole request/response bodies.
- Include synthetic fixtures, detection-matrix coverage, malformed/oversized-record regressions, cluster-confirmation keyboard tests and signed ingest/rebuild/seal/export coverage.
- Format impact: no additional format change beyond the cluster/common vocabulary extensions described below.

### Cluster-qualified common events

- Extend the current common event vocabulary with bounded orchestrator,
  container, group and privilege fields and cluster/namespace-qualified entities.
  Raw producer cluster IDs remain separate from acquisition identity.
- Add an exact `cluster` query filter, signed partition pruning and row filtering
  inside overflow buckets. Hash verification and all query limits remain intact.
- Cluster artifacts carry an explicit optional column/metadata extension;
  non-cluster Parquet files retain their physical bytes. Unmapped cluster sources
  retain originals and commitments without projecting arbitrary request bodies.
- Format impact: the expanded common vocabulary changes the mapped target-contract
  digest and current profile/envelope/export vectors. V7 framing and seal
  challenges are unchanged. Use the creating version for another contract, or
  re-ingest verified originals into a new case; no migration is introduced.

### Kubernetes ingestion foundation

- Bind explicit, bounded cluster acquisition context to source manifests,
  decoded-record commitments and reconstruction. Cluster claims cannot grant
  permissions or silently replace analyst-confirmed identities.
- Add deterministic cluster partitions with 64 ordinary values by default,
  a maximum of 1,024 and signed overflow buckets. Raw cluster identifiers never
  become directory names.
- Format impact: current source manifests and record-set commitments gain an
  optional cluster-context extension; records carrying cluster context include
  it in their canonical hash. Sources without context retain their bytes.

### Case allocations

- Add signed defaults for new cases in `/settings limits` and signed per-case
  token, tool-call and reserved cloud-byte allocations in `/budget`. Organization
  ceilings remain mandatory; increases need explicit Analyst confirmation.
- Use 2,000,000 tokens and 1,000 calls by default, retaining all fixed maxima and
  existing cloud-transfer controls. Existing policy files are not rewritten.
- Show consumption and 80% warnings, and retain completed work with a tool-free
  or local summary when an allocation is exhausted. Missing provider usage is
  labeled unavailable; costs are shown only when supported by usage/pricing.
- Format impact: case creation records include the initial allocation and later
  changes use `CaseBudgetChanged` receipts. Existing signed-entry and export V7
  framing are unchanged. Cases without a recorded allocation require explicit signed confirmation in
  `/budget` before new model/tool work; recorded consumption is retained.


## 0.4.1 — Expanded forensic skill catalog

**Format impact: none.** Case, export V7, skill package and definition formats
are unchanged. The three skills shipped in 0.4.0 retain their exact package
hashes. Adding candidates changes the bundled inventory commitment for new
skill snapshots; recorded snapshots remain self-contained and verifiable.

### Added

- Ten data-only methods: S3 data exfiltration, Azure Entra identity compromise,
  GCP service-account abuse, Windows ransomware, lateral movement and persistence,
  Linux webshell and persistence, network C2 beaconing, and malware execution
  triage. The binary now includes 13 methods.
- Each new method includes a bounded investigation sequence, common-schema
  query starting points, conditional ATT&CK proposals, collection requirements,
  confirmation criteria and common false positives. They declare only local
  evidence reads and finding-proposal tools.
- Per-method scripted integration episodes cover real ingestion, progressive
  loading, local queries, analyst confirmation, verification, sealing and
  independent export verification. Hostile-evidence tests cover undeclared tools
  and out-of-scope reads with an obedient fake model.
- The Azure/GCP tests reuse pinned, attributed HuntEval episodes. Expected answers
  remain evaluator-only, outside evidence, skills and model requests.

### Coverage and limits

All methods remain experimental and synthetic-tested. Native Entra has no
specific semantic mapper; use original JSON fields or explicitly producer-normalized
ECS/configured UDM. Native GCP and Zeek/Suricata retain extraction-only coverage.
S3 policy/ACL changes, Windows task/WMI telemetry and several Linux configuration
artifacts need original-field review or additional collection. A missing mapping
is reported, never filled with an invented classification. This release adds no
parser, mapper, credential, dependency or remote-provider default.

## 0.4.0 — Signed forensic skills

**Format impact: breaking.** Case methodology adds `SkillSnapshotV1` and
Agent-signed `SkillLoadV1` records. Export V7 replaces V6 and includes the exact
signed installation admissions referenced by a case. The export port is now
`export_case`; versions belong to the file header. Parquet V3, existing audit
entry encoding and seal inventory V2 are unchanged. Pre-1.0 minor versions may
change formats without migration. Retain the creating executable or re-ingest
verified originals into a new case.

### Added

- `/skills` previews local packages and signs installations, replacements,
  activation changes and explicit restoration of approved files. There are no
  executable skill plugins or automatic downloads.
- Included Windows triage, Linux triage and AWS credential-compromise methods,
  available as slash commands and through progressive agent selection.
- Only active names and descriptions reach the model initially. Policy-checked
  `skill_read` loads bounded, guarded resources after durable Agent-signed
  receipts. Skill contents never enter system messages or become evidence.
- Self-contained export V7 verifies skill packages, original/screened ranges,
  admission proofs and signer identities without a keyring.

### Changed

- Release binaries strip debug symbols without changing executable code, data,
  unwind information, security controls or signed data formats. A controlled
  comparison reduces the Linux executable from 52.47 to 39.40 MiB.
- Method-assisted calls must be declared by the active skill and still pass
  policy, case scope, organization ceilings, taint checks, approvals and budgets.

### Validation and limits

The three included methods complete synthetic scripted investigations through
real ingestion, evidence queries, analyst-confirmed findings and sealed,
independently verified exports. This does not validate a real model's reasoning
or a real connector deployment. No model or connector is enabled by default.
This remains a pre-release for synthetic-data evaluation, not real incidents.


## 0.3.0 — Common events and one ingestion pipeline

**Format impact: breaking.** This minor release reads and writes the current
mapped V3 case artifacts and export V6 only. It does not open, verify or export
v0.2 cases or earlier exports. Keep the executable that created an earlier case,
or verify its originals with that version and ingest them into a new case with
0.3. No automatic migration runs when opening a case; previous approvals,
findings and seals stay with the original case. See [earlier-version cases](docs/development/case-migration.md).

### Added and changed

- Add validated common-event categories, types, outcomes and role-bearing entities, fixed code tables and bounded typed filters in the existing evidence tools. Source provenance and identity scopes distinguish PID reuse and actor/target observations.
- Separate every format decoder from its identified source mapping. Signed source sets, mapping profiles and run receipts bind original fields, the selected interpretation and V3 artifacts. Full reconstruction reproduces the pinned pipeline; authentication-only verification remains explicitly distinct.
- Include semantic mappings for Windows EVTX, Linux authentication/auditd/HTTP, CloudTrail, ECS and OCSF. Other DFIR, syslog, journald, network and declarative sources retain searchable extraction without inferred classifications. A cross-source test finds Windows 4625, Linux Failed password and CloudTrail ConsoleLogin failures with their documented roles.
- Use one mapped writer in CLI, TUI, demo and object ingestion. Remove historical writers/readers, precision migrations, retired mapping interpreters, compatibility preferences and obsolete test/fuzz paths. Retain current golden bytes and inward dependency checks.
- Scale ingestion and query workers with available CPUs, a global memory allowance and the analyst's configured cap. Decode independent records within NDJSON, CSV and text sources; preserve real offsets and source members. Prepare pure mapped records and finish independent partition writers in bounded parallel lanes, while canonical accounting and signed commits stay ordered. Ordered sources overlap decoding and writing; disorder keeps private case-local sorting.
- Decode EVTX chunks concurrently inside the isolated helper without a new thread-pool dependency. Linux allows only the required same-process thread lifecycle; process creation, exec, network and unrelated file access remain blocked. Windows retains serial source starts and one verified network witness per session. Output order and signed bytes are checked across worker counts.
- Add experimental Elastic Query DSL search and Elastic Security alert reads with a read-only API key, explicit indices and optional connector CA. Add experimental Google SecOps structured UDM search with an explicit service-account key and RS256 JWTs. Its default event-account scope stays account-filtered; explicit instance scope requires analyst confirmation, an organization ceiling, signed per-source case context and a persistent TUI warning. Detection reads use one configured rule and a bounded server-side UTC window, retaining partial-result markers. Credentials stay in the keystore, native roots and hostname checks stay enabled, and returned events enter the signed source/mapping pipeline. No remote model or connector is enabled by default.
- Remove unused infrastructure keystore loading and dependency edges. The configured OS/file backends remain the only production signing/secret routes; missing backends fail closed.

### Fixed

- Update rusqlite from 0.32.1 to 0.41.1 and its SQLite binding from libsqlite3-sys 0.30.1 to 0.39.1, retaining parameterized queries and signed custody checks.
- Count oversized whitespace-prefixed source records as rejected and preserve subsequent source ordinals and offsets. The affected development source-decoder path was not in v0.2.0.
- Apply declarative JSON field budgets to array elements as well as object members. v0.2.0 already applies the aggregate budget and is not affected.
- Mark auditd terminator-only groups as partial. v0.2.0 already marks groups without substantive records partial and is not affected.
- Exercise empty-entity and three-artifact sources explicitly on every platform, including concurrent publication and artifact hash checks.

### Known limits

This is a pre-release for evaluation with synthetic data, not real incidents or
sensitive evidence. H5 was accepted by analyst decision after a real DeepSeek
greeting; investigation citations, follow-up, streaming and verification details
remain unrecorded. No connector has been validated against a real test service.
Some sources have extraction-only mappings; classification coverage is explicit.
Windows 10/11 EVTX confirmation remains [community work](https://github.com/ns2switch/irmind/issues/189).
Apple notarization and Windows Authenticode remain unavailable; releases carry
Sigstore signatures, GitHub provenance, SBOMs and checksums. Co-observation size,
dense-entity lookup and deliberately worst-case path work remain tracked in
[issue #37](https://github.com/ns2switch/irmind/issues/37) and the
[release benchmark record](docs/development/benchmarks.md).

## 0.2.0 — Modular parsers and precise evidence

**Format impact:** Breaking: artifact V2 and export V5 add precision and partition formats. Its historical V1 reader/migration support applies only to that release.

- Add experimental Zeek TSV/JSON and Suricata EVE modules with bounded detection, streaming parsing, precise timestamps, host-aware partitions, source provenance and synthetic contract fixtures. They were not distributed in v0.1.x. Source detections remain unconfirmed findings.
- Write artifact V2 by default in the CLI, TUI and isolated demo. Preserve UTC microseconds, residual nanoseconds, source precision and stable source/record ordering. Bound host partition cardinality at 64 ordinary hosts by default, with a hard ceiling of 1,024 and signed overflow.
- Keep existing V1 cases readable without migration. Offer explicit, verified precision migration for open cases, retain historical signed generations and use export V5 for V2/mixed cases. See the [V1 → V2 migration guide](docs/development/case-migration.md).
- Improve ordered-source ingestion, bounded natural-run merging, authenticated global timeline pruning and entity extrema handling. Release-profile cloud/chronological benchmarks meet the 900-second 15 GB ingestion gate; the disordered stress corpus uses the separately approved 1,350-second gate, with unchanged query limits.
- Ship the isolated `irmind-evtx` helper with the signed release packages, its own SBOM and unsafe inventory. Linux requires Landlock/seccomp; macOS and Windows require verified native containment. Windows uses one verified network witness per session and canonical serial source starts; hashing remains parallel. Each file is capped at 4 GiB, 8,000,000 records and a 600-second invocation deadline, with complete rejection on a limit.
- Warn non-disruptively when a retired pre-0.1.6 parser may have omitted records. Existing signed bytes still authenticate; re-ingest verified originals into a new case to rebuild with current readers.
- Publish Sigstore bundles, GitHub provenance, main/helper SBOMs, checksums and user-level installers for Linux x86-64/aarch64, macOS arm64 and Windows x64.

### Migration notes

Opening a V1 case never migrates it. Migrate only when source subsecond precision or host-aware queries are useful, verified originals and the pinned parser remain available, and the case is open. Keep space for both generations. Sealed cases stay immutable. This precision migration does not apply the proposed common event schema; semantic migration is deferred. The alternative for retired parsers is a new case with verified originals.

### Known limitations

This remains a pre-release for evaluation with synthetic data, not real incidents or sensitive evidence. H5 is accepted by analyst decision after a real DeepSeek greeting; investigation citations, follow-up, streaming and verification details remain unrecorded, and no connector has been validated against a real test environment. Windows 10/11 EVTX validation remains [community work](https://github.com/ns2switch/irmind/issues/189). The decoder streams with stable measured memory; the complete ingestion host does not yet have constant metadata memory. Co-observation disk use and worst-case query work remain tracked in [issue #37](https://github.com/ns2switch/irmind/issues/37) and the [bounded-metadata proposal](docs/development/parquet-bounded-metadata-design.md). Native Apple notarization and Windows Authenticode are not available. Elastic, Chronicle and the typed common event schema belong to v0.3 and are not included here. No model or connector is enabled by default.

## 0.1.6 — Complete bounded JSON ingestion

**Format impact:** Case/export encodings unchanged; affected parser identities and declarative reader bindings change, and affected historical parser implementations are retired.

### Known issue fixed

- Correct bounded document probing so large single-line JSON exports retain every source byte. In v0.1.1–v0.1.5, JSON files without a `.jsonl` or `.ndjson` extension could fail or omit records when their first line exceeded 4 MiB. The same reader was used for cloud object ingestion. A valid original hash and signed chain authenticate the stored bytes; they do not prove that a parser extracted every record.
- Use `json-stream-v3` for new JSON ingestion. Version the affected ECS, OCSF, DFIR and declarative readers, and count oversized line records as rejected instead of treating a whitespace prefix as an empty line. Preserve record, field, depth and cancellation limits.
- Retire historical parsing implementations. To regenerate evidence with current readers, create a new case and ingest verified originals again. Existing signed entries and export encodings are unchanged; authenticating existing bytes does not require a retired parser. Reinstall approved declarative definitions to select their current reader identity.
- Bind object-storage parsing to the logical object name and reconstruct retained copies from case-local originals. Record the actual parser identity in every new source manifest.
- Add streaming 5, 50 and 200 MiB regressions, signed local/object-ingestion checks and separate current-version format goldens; retain historical golden bytes.

## 0.1.5 — Automatic demo presentation

**Format impact:** No case, export or definition format change.

- Replace the command-driven tutorial with an automatic ten-scene presentation. The real TUI types and runs commands against its isolated synthetic case, with full-width narration and a highlighted investigation area.
- Add Enter, Backspace, Space and Esc navigation, proportional reading time, a clear minimum-terminal notice, visible failures and final exploration/start/exit choices.
- Show scripted responses as a word-preserving stream with source hashes. Sign the simulated enrichment and custody confirmations only within the explicitly isolated demo; no provider is probed and no network is used.
- Exercise every scene in automatic and manual PTYs, including cancellation and terminal/data cleanup. Refresh the complete VHS recording and scene captures from the actual versioned binary.

## 0.1.4 — Card expansion

**Format impact:** Case/export encodings unchanged; declarative parser definitions and additional parser identities are introduced.

- Make Ctrl+O expand or fold the selected card from any case-screen focus, falling back to the last expandable card. Keep text drafts and open forms intact.
- Add `/expand` to the shared command menu and help as an alternative for terminal keymaps that intercept Ctrl+O.
- Reveal full multiline notices when expanded; retain guarded display and unchanged policy, custody and signed formats.
- Add TestBackend and cross-platform PTY regression coverage. Native terminal applications, SSH and tmux still need interactive confirmation; CI PTYs are not represented as those manual tests.

- Add the experimental Linux parser module for authentication, auditd, journald JSON and HTTP common/combined exports, with per-ingestion time, bounded partial-event correlation and preserved source precision.

- Add the experimental syslog module: bounded RFC 5424/RFC 3164 and gzip parsing, explicit signed legacy-time context, detection and reproducible Parquet ingestion.

- Add an experimental declarative parser for bounded CSV, JSON/NDJSON and regex formats, with signed definition installation and recovery, pinned reconstruction, and a guarded ten-row preview in `/parsers`.

## 0.1.3 — Guided demo

**Format impact:** No case, export or definition format change.

- Guide the isolated synthetic demo through ten event-driven steps, from evidence exploration and signed approval to findings, custody verification and export.
- Keep one current instruction in the guide. Show completed ingestion as a fact, without competing command suggestions.
- Add command-specific help and optional empty-state hints, with a full tutorial PTY test on Linux, macOS and Windows.
- Record H5 as complete by analyst decision after a natural greeting with real DeepSeek and no unnecessary tool calls. Investigation citations, follow-up, streaming and verification remain pending analyst records; the real-connector validation remains pending.
- Refresh synthetic tutorial screenshots from the actual 0.1.3 binary.

## 0.1.2 — Demo ingest repair

**Format impact:** Case/export encodings unchanged; additional parser identities are introduced.

- Show a persistent completion or actionable error after the demo's background ingestion, so the case never appears stuck after evidence is found.
- Use the same parser detection registry and signed `SourceManifestV2` path as ordinary case ingestion in the demo.
- Add experimental, auto-detected Elastic Common Schema NDJSON and OCSF JSON/Parquet parsers as optional Cargo modules compiled by default. Both normalize bounded records into signed local Parquet and preserve source provenance; ambiguous Parquet detection asks the analyst.
- Add experimental parsers for Velociraptor, Hayabusa, Chainsaw, Plaso, and common Eric Zimmerman CSV exports, with synthetic fixtures and parser detection.

## 0.1.1 — Community preview

**Format impact:** SourceManifestV2 adds signed parser/detection metadata; existing export encodings are unchanged.

- Offer a temporary `/demo` case with synthetic HuntEval data and a scripted model, without a configured key or network connection.
- Keep exact greetings conversational by withholding tools, while preserving the structured, signed agent conversation.
- Select the compiled parser from a bounded content sample. Sign its version, detection confidence, selection mode, and bounded rejected-record count in `SourceManifestV2`; existing V1 manifests remain verifiable.
- Provide user-level installers for Linux, macOS, and Windows, and a Linux aarch64 binary. The installers check release hashes and verify Sigstore and GitHub provenance when the tools are available.
- Publish SHA256SUMS, keyless Sigstore bundles, GitHub build attestations, and an SPDX SBOM. Tag builds smoke-test both installers in clean Linux and Windows runners.

Manual validation with a real model and a real connector remains pending. Use synthetic data only; this version is not suitable for real incidents or sensitive data.

## 0.1.0 — Pre-release (2026-10-31)

**Format impact:** Initial case, source-manifest, Parquet and export formats.

- Investigate a signed case from the terminal, with a guided first run, conversation, approvals, findings, and evidence views.
- Enforce case and organization scope before remote tool calls; require an analyst signature for external enrichment.
- Keep a signed chain of custody and source manifests; verify, seal, and export cases with an expected public-key fingerprint.
- Ingest approved local and cloud-exported logs into signed, partitioned Parquet; query bounded graph and timeline results directly with Arrow and Parquet, without DuckDB.
- Preserve case conversation and tool-call IDs across model rounds, answer ordinary questions without unnecessary investigation, and summarize work when a turn reaches its limit. Keep case context and evidence out of the trusted system role.
- Evaluate deterministic retrieval against the synthetic HuntEval corpus, including events hidden in 1 GB and 15 GB background corpora.
- Speed up Parquet graph queries with sorted entity rows, row-group pruning, and a signed co-observation artifact. Record the remaining disk and worst-case path work in the post-release issue.
- Add optional, fingerprinted custom CA certificates per connector while retaining TLS hostname verification.
- Configure model, connector, and keystore backends in the TUI. No model or connector is enabled by default.
- Build unsigned binaries for Linux, macOS, and Windows with SHA-256 checksums.

This pre-release is published without the manual H5 validation with DeepSeek or a connector test against a real test environment. Both remain pending and may lead to fixes in 0.1.x. Do not use this version for real incidents or sensitive data. The signed co-observation artifact's disk use, entity lookup latency, and worst-case three-hop path query are tracked in [issue #37](https://github.com/ns2switch/irmind/issues/37). Binaries are unsigned; verify the supplied SHA-256 checksums before use.
