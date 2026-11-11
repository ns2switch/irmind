# Design decisions

## Pre-1.0 format policy

Context: pre-release compatibility layers obscure current implementation boundaries and delay source decoding and mapping work. Formats are still being designed.

Decision: until formats stabilize, expected around v0.6–v0.7, each minor version may change case, export, parser-definition and mapping-definition formats without migration or historical readers. Keep the exact creating IRMind version to open, verify or export a case, or re-ingest its verified originals into a new case. Parser-version retention and long-term format compatibility will be decided at stabilization, before 1.0; earlier two-minor retention proposals are not current policy.

Inside a supported version, all signatures, hashes, custody verification, ContentGuard, policy ceilings, approvals, TLS checks and resource limits remain mandatory. Unsupported formats are rejected before case operations, with a safe creator-version hint when available. Definitions using a retired interpreter are disabled with a visible warning and cannot prevent startup.

V3 is the sole target writer for CLI, TUI and demo. Remove V1/V2 readers and writers, old exports, precision migrations and interpreter V1 in separate area-specific changes. First provide a SourceDecoder and an extraction-preserving mapping for every parser; only then remove its legacy route. Keep goldens and fuzzing for the retained current formats. Preserve historical design documents as explicitly historical records.

The analyst moves the 1,025-host stress ingestion miss, relative query regressions and result materialization to performance follow-up work. The evaluator no longer compares V3 with V2. Keep measuring absolute cloud/chronological ingestion targets and ordinary query deadlines. Release v0.3.0 requires phase B, cleanup, Elastic and Chronicle; the tag remains a separate review checkpoint.

Consequences: earlier compatibility, migration and relative-activation decisions below are historical where they conflict with this policy. Each release changelog states its format impact. This decision permits removing obsolete code, not weakening a control or relabeling failed verification as success.


Proposed, awaiting analyst review: use one explicitly versioned artifact value at the existing storage boundary, plus additive typed parser callbacks, for [mixed V1/V2 ingestion](parquet-v2-port-transition.md). The recommendation avoids a second custody pipeline; it does not authorize changing V1 bytes. No port is changed by this documentation PR.

This page is for maintainers reviewing tradeoffs that shape the current build. Each row states the context, choice, consequence, and decision date. The [reference plan](plan.md) holds acceptance criteria.

| Context | Decision | Consequence | Date |
| --- | --- | --- | --- |
| A provider can start an unwanted investigation after a greeting even when the prompt tells it to reply briefly. | Offer no tools for an exact greeting and deny any unadvertised tool call before dispatch. Keep the current structured conversation and configured round limits. | A greeting stays conversational without granting the model a tool path; requests that contain more than a greeting retain their normal tools. | — |
| Multiple attacker-controlled log formats cannot safely share a single implicit parser. | Compile each parser as an optional Cargo module, detect from at most 64 KiB, auto-select only a unique high-confidence result, and require an analyst choice otherwise. Record the parser, version, confidence, and selection mode in a new `SourceManifestV2`; continue verifying existing V1 entries. | A minimal build may omit any parser and then refuses ingestion. Mixed-parser reconstruction uses the signed selection and fails if its exact version is unavailable. A declassification challenge with parser location uses a separate v2 domain. Line-delimited JSON counts malformed rows and signs a bounded untrusted sample; malformed monolithic JSON is rejected because safe resynchronization is not possible. | 2026-10-31 |
| Incident response needs reusable methods and bounded parallel investigation. | Treat signed forensic skills and policy-bound subagents as core product capabilities. Approve their design documents before implementation. | Skills cannot grant permissions; subagents inherit case scope, sign as Agent, and route approvals to the analyst. | — |
| A graphical interface and unattended automation need a stable headless engine. | Develop the graphical interface, gateway, and watches in a separate repository that consumes IRMind through a versioned engine API. | This repository owns the secure engine and terminal client; the other project cannot access signing keys directly. | — |
| Checksums alone do not provide release origin or native platform trust. | Add Sigstore keyless signatures and attestations, then native Developer ID signing and notarization on macOS and Authenticode through SignPath Foundation on Windows. | The earlier unsigned-binary decision remains historical for 0.1.0. A protected release process and maintainer approval are required before native signing; no credentials are configured by this roadmap. | — |
| Entity and graph queries over the direct Parquet reader spent most of their time scanning co-observed records. | Write entity rows ordered by kind and value within bounded batches, enable value-column Bloom filters, and sign a separate co-observation Parquet artifact for each source partition. Keep legacy entity v1 artifacts readable and reproducible; new artifacts use entity v2 and co-observation v1 schema labels inside the existing signed artifact envelope. | Neighbor and path queries can read only matching co-observation rows without a second full entity scan. Ingestion and disk use increase; every selected artifact still passes SHA-256 verification before reading, and old cases use the previous query path. | 2026-10-31 |
| Corporate or lab connectors may use a CA absent from system roots. | Allow an optional per-connector CA PEM for Splunk, MISP, CrowdStrike, SentinelOne, and S3-compatible storage. Sign its SHA-256 fingerprint with the existing configuration snapshot and check it before creating the TLS client. | The PEM adds trust only for that connector; HTTPS, hostname verification, bounded responses, and disabled redirects remain mandatory. A changed CA file fails closed until the analyst approves its new fingerprint. | 2026-10-30 |
| The model repeated tools after receiving concatenated case text without protocol-linked results, and a four-round error discarded progress. | Replay signed conversation history as labeled, guarded user data and return each current-turn assistant tool call and guarded tool result under the provider's call ID. Treat analyst text as conversation; cap turns with a policy setting (25 by default, 100 maximum), deduplicate identical calls, and request a final no-tool summary at the round limit. | New signed `FinalAnswer` and `ConversationSummary` events preserve screened history without changing existing event wire names; raw provider frames remain audit-only. DeepSeek thinking is disabled when tools are offered because its tool protocol expects reasoning to be returned, which IRMind forbids. | 2026-10-30 |
| Case context and model-generated summaries in a system message would give untrusted content instruction priority. | Reserve system messages for fixed IRMind instructions. Send case data, prior answers, and summaries as nonce-delimited untrusted user messages before the current analyst turn. Anthropic rejects an untrusted delimiter in any system message. | The signed log and tool protocol stay unchanged; the provider sees historical replies as labeled data rather than instructions. | 2026-10-30 |
| Configuring a model through separate screens made defaults invisible and let slash input reach the command parser. | Use `/settings` as the sole configuration entry, route legacy commands there, and keep all values in focused form fields with bracketed paste. Show provider URL defaults and normalize path separators before validation. | The command parser runs only in the home or case composer; no LLM or connector is enabled by default. | 2026-10-30 |
| The evidence guard neutralized a trusted configuration URL while rendering the module detail. | Escape configuration labels and entered non-secret values for terminal output; keep `ContentGuard` on external evidence and model text. | Default URLs remain visible without allowing terminal controls, and attacker-controlled evidence still receives the full guard pipeline. | 2026-10-30 |
| Analysts need to choose among documented compatible model services without new product adapters. | Add local and remote presets backed by the existing OpenAI-compatible module, with native Anthropic, DeepSeek, and OpenRouter entries retained. Confirm before a remote model-list or synthetic test request sends its API key; saving a remote model still needs signed egress confirmation. | Model listing can fail and falls back to manual ID entry; compatibility and tool calling depend on the chosen model. Azure OpenAI URLs requiring `api-version` remain unsupported. | 2026-10-30 |
| Preferences were split from connector setup. | Put resume, mouse capture, and an optional auto/light/dark theme in `/settings preferences` and the non-secret signed configuration. | The old serialized configuration omits `theme` until the analyst selects it, preserving the existing signed bytes; no signed event identifier changes. | 2026-10-30 |
| Model proposals cannot set their own privilege. | `Tool` determines risk; `ProposedCall` omits risk. | Policy owns authorization. | 2026-10-23 |
| The derived graph already has signed Parquet artifacts, while a bundled native query engine increased build cost. | Replace DuckDB with bounded Arrow/Parquet scans, preserving source and artifact signatures, exact query limits, and explicit legacy migration. | The same-runner cold release test build fell from 42m 11s to 8m 06s and the binary from 104 MB to 44 MB. On synthetic 15 GB data, all query p95 values were below 10 s, but neighbors and path slowed to about 8.5 s and need targeted optimization. See [benchmarks](benchmarks.md). Historical signed graph identifiers remain verifiable. | 2026-10-30 |
| Investigation sources include attacker-controlled text. | Mandatory guard, provenance, and fail-closed screening. | Original evidence stays local; detection is not perfect. | 2026-10-23 |
| Later unattended agents need distinct authority. | Analyst and Agent use separate Ed25519 keys and `ExecutionMode`. | Only analyst signatures resolve approvals. | 2026-10-23 |
| Product connectors must be replaceable. | Static Cargo modules implement application ports. | No runtime plugin loader; modules remain explicitly selected. | 2026-10-23 |
| Remote I/O and local custody have different costs. | Remote ports are async; local ports are synchronous and use `spawn_blocking` from async use cases. | Local work does not block the runtime. | 2026-10-25 |
| Native key storage may be unavailable over SSH. | Select `os` or encrypted `file` explicitly per signing and secret capability. | No silent fallback; an unavailable selected backend stops startup. | 2026-10-25 |
| The file keystore needs private writes without an adapter dependency. | Move ACL and durable-write helpers to `irmind-fs`. | Infra and keystore-file share one audited filesystem boundary; adapters cannot depend on adapters. | 2026-10-26 |
| Key migration can happen before the first case. | Record it once in a global signed operational chain. | Startup verifies the chain; historical case operations remain intact. | 2026-10-26 |
| Active connectors may retain a changed credential. | Warn in the TUI and offer `/restart` to rebuild the session. | The new value takes effect only after the composition root restarts. | 2026-10-26 |
| Letter shortcuts in the TUI obscured the command input and caused accidental actions. | Printable keys always edit the active field; actions use the single slash-command registry or explicit numbered confirmation. | Navigation uses Enter, Esc, arrows, Tab, PgUp/PgDn, Ctrl+C, Ctrl+K, and Ctrl+O consistently across screens. | 2026-10-29 |
| Analysts could not select missing providers from a minimal binary. | Compile all existing product modules and both keystores in the normal build, but enable no LLM or connector by default. | Minimal builds use `--no-default-features` together with an explicit keystore feature; the safety requirement for a signer and secret backend remains enforced. | 2026-10-29 |
| First-run model setup required manual module editing. | Offer optional `/model` setup in the TUI, with bounded Ollama discovery, masked remote keys, a synthetic connection test, and signed confirmation before remote egress. | Secrets remain in the selected backend; no model is selected until the analyst saves it. | 2026-10-29 |
| A separate search field and framed home list made the start screen feel unlike the case conversation. | Use one home composer for live case filtering and slash commands, an unframed case list, and centered dialogs that hide the background composer. | The presentation changes without changing case use cases or signed formats; `/cases <status>` handles status filtering. | 2026-10-30 |
| Analysts commonly return to the case they just worked on. | Keep a private local `last-case` reference outside custody and reopen it only after the normal case-chain verification; skip sealed or missing cases and show failures on the home screen. Default `resume_last_case` to true, with an explicit `/config` toggle. | The reference has no evidentiary meaning and cannot bypass verification; automation keeps its existing startup behavior. | 2026-10-30 |
| Creating a local case should not require entering a remote scope. | Make title and severity the primary `/new` step; place remote sources, targets, prefixes, and UTC bounds in an optional second step with inline validation against the policy ceiling. | Local cases need two fields, while remote scope remains explicit and bounded. | 2026-10-30 |
| Technical module IDs and binary-only status hid the setup path. | Group `/modules` by capability, show readable names and active, disabled, missing, or uncompiled status, and expose technical IDs, public parameters, credentials, and features in the detail pane. | Operators can identify what to configure without seeing secret values. | 2026-10-30 |
| Local and remote TLS needs corporate roots. | Rustls uses native certificate roots; keyless local models may use loopback HTTP. | No system OpenSSL; platform-verifier checks are not fully replicated. | 2026-10-25 |
| A crash during sealing can leave two stores out of sync. | Sign the seal separately, persist seal intent first, and reconcile on startup. | Verification reports unresolved inconsistency. | 2026-10-25 |
| Sealed cases cannot accept more case-chain entries. | Record cancellations in a separate signed operational chain. | The case seal remains immutable. | 2026-10-25 |
| Analysts need one primary workflow. | `irmind` opens the TUI by default; CLI and TUI share application use cases. | Automation remains available through subcommands. | 2026-10-25 |
| Export and package verification must not depend on presentation. | Add local `CaseExporter` and `ExportVerifier` ports. | CLI and TUI use the same checks; package verification needs no keyring. | 2026-10-25 |
| Provider selection can expose evidence. | No LLM enabled by default; secrets are read by the composition root and injected. | Provider approval is a separate operating decision. | 2026-10-25 |
| The v0.1.0 pre-release provided checksums but no publisher identity or build provenance. | Starting with v0.1.1, use GitHub Actions OIDC and Sigstore cosign to sign every release binary and `SHA256SUMS`, attest each binary and the SPDX SBOM, and publish the bundles with exact workflow and tag identity checks. Pin cosign 3.1.4 because the action's bundled 3.0.6 is affected by GHSA-fx35-mq7g-6g98. | Reproducible checksum verification gains a verifiable publisher and build workflow. Apple notarization and Windows Authenticode are still absent, so Gatekeeper and SmartScreen may warn. Keep v0.1.0 documented as unsigned. | 2026-10-31 |
| Repeated release builds and full platform matrices slow ordinary review. | Run Linux checks on every PR and main merge; run platform tests on relevant PRs, nightly after main changes, tags, and manual requests. Build binaries and cross-verify exports only on tags and qualifying nightly runs. | The main rules require DCO and Linux; nightly and platform-specific PRs still exercise Windows and macOS. Only tag releases enter the signing and publishing job. Cache keys use the platform and lockfile hash. | 2026-10-28 |
| GitHub runner images add moving Rust toolchains, and PR caches can evict the main build cache. | Keep only pinned Rust 1.95.0 in CI; key the cache by platform, `Cargo.lock`, while Cargo fingerprints handle manifest and source changes. Keep Clippy and nextest on the existing `ci` profile, restore caches in PRs, and save them only from `main`. Produce Cargo build timing reports only on manual diagnostics. | Exact cache hits preserve bundled SQLite and Rust dependency artifacts when the lockfile is unchanged; ordinary PRs still run Clippy and nextest without an extra build. | 2026-10-28 |
| Analysts need settings that survive a TUI session without storing secrets. | Save versioned, non-secret module settings in a private `config.toml`; resolve flag, environment, file, then defaults. Check its hash against the last signed operational change. | Secrets stay in the selected keystore; unknown fields, secret fields, and unapproved file edits fail closed. | 2026-10-26 |
| Changing an active destination can expose case data. | Require attended analyst confirmation and a signed global operational event before enabling an LLM or connector or changing its active public settings. | The TUI composes a new session in the same process; temporary CLI and environment overrides remain read-only there. | 2026-10-26 |
| A crash can occur after the signed configuration event but before `config.toml` is replaced. | Store the complete canonical non-secret configuration in each new signed approval event; offer explicit restoration or reviewed acceptance before case work. | Older hash-only events still verify but cannot restore missing content. Automation fails closed until the TUI resolves a mismatch. | 2026-10-27 |
| Flags and environment settings may redirect a session without changing the saved file. | Show each effective egress override against its saved value before a TUI session; sign accepted overrides in the global chain. Automation signs effective overrides before running. | Rejection uses saved settings, and the status bar marks accepted overrides. | 2026-10-27 |
| Spanish translations cite their English source commit. | Check each citation against the last commit to change its source and warn on a stale translation. | A rebase merge can change commit IDs, so documentation PRs should use merge commits when citation hashes must remain exact. | 2026-10-26 |
| Public contributions need clear provenance. | Dual license MIT OR Apache-2.0 and require DCO on every PR commit. | CI checks author-matching sign-off. | 2026-10-25 |
| Free-form model SPL is difficult to constrain. | Use a provider-neutral structured SIEM query with an allowlist of fields, operators, and aggregations; the Splunk module maps fields and escapes values. | The old `query` argument is denied, including pending calls, while historical signed entries remain verifiable. No remote port or signed serialization changes. | 2026-10-28 |
| Incident reports must not promote unreviewed graph events into findings. | Keep graph events exploratory; report only analyst-confirmed timeline events and findings, each with evidence references. | Legacy signed finding payloads remain readable; new typed details add IOC, hypothesis, and technique fields. | 2026-10-27 |
| Case scope needs projects without breaking signed v1 strings. | Add v2 scope encoding and an optional policy TOML ceiling for sources, accounts, projects, hosts, and UTC window. | The ceiling denies calls outside it, including pending approvals; case creation and scope changes above it fail. Existing broader cases run within the intersection and show a TUI warning. | 2026-10-27 |
| Finding metadata is signed as strings but must be validated by meaning. | Use domain types for UTC instants, lowercase evidence hashes, and IOC values validated by kind; retain existing signed JSON strings at the application boundary. | Invalid dates, hashes, IP addresses, domains, hash lengths, users, and keys fail before a finding enters the case model. | 2026-10-27 |
| Audit event names are part of the signed format. | Pass typed event kinds and origins through the engine; convert to wire names only in the domain kind mapping and the origin mapping. | A CI check rejects new event-kind literals outside the mapping; historical signatures remain verifiable. | 2026-10-27 |
| Long investigations need navigation without rebuilding a chat transcript each frame. | Cache guarded conversation cards and render only the visible window; keep the case sidebar optional. Mouse capture is an explicit non-secret setting, enabled by default. | Streaming preserves the reader's scroll position; operators can disable mouse capture to select terminal text. The unset setting keeps the prior signed configuration encoding. | 2026-10-27 |
| Rechecking every prior evidence blob during each ingest made multi-file cases expensive. | Fully verify the signed case chain on open and explicit `verify`; during ingestion, validate the checkpoint and newly signed entries and evidence. Screen indexed text when queried. | Custody guarantees remain unchanged; explicit verification still checks the complete chain and original copies. | 2026-10-28 |
| Real cloud cases contain 15–500 GB of logs, beyond the original copied-evidence path. | Use signed `SourceManifestV1` and `ParquetArtifactV1` records, explicit optional copies, and partitioned Parquet as the derived local store; Bounded Arrow scans read only signed, hash-checked IRMind-produced Parquet. Use a streaming v4 export with optional originals and a detailed verifier; preserve v3. Read S3, GCS, and Azure Blob in the MVP; defer source-side query execution. | Uncopied originals cannot be verified offline; sampling reports limited coverage. The versioned payloads extend the case chain without changing its canonical entry format or the seal challenge. See [the custody format](parquet-custody-design.md). | 2026-10-28 |
| Repeating thousands of audit-signature checks before every Parquet query dominates query latency. | Cache the authenticated artifact catalog per open case, keyed by the signed audit head and SQLite `data_version`; revalidate the chain when either changes. Hash every selected Parquet file before an Arrow scan reads it. | A changed prior audit row from another SQLite connection invalidates the cache even if the final hash is unchanged; explicit `verify` still checks the complete chain. The cache holds only derived metadata, not original evidence. | 2026-10-28 |
| A common entity in a 15 GB case makes an exhaustive neighbor self-join exceed the 10-second query budget. | Limit co-observation to 4,096 matching records and label the result as partial whenever more records match. | The counts are exact for the selected records; a partial result never claims to rank all neighbors in the case. The signed Parquet artifacts are still verified before the bounded query. | 2026-10-28 |
| A direct-only Parquet path query would lose the existing graph's multi-record paths. | Traverse up to three hops, expanding at most 200 entities and 50 neighbors per entity within a 10-second query budget. | A missing path is reported as truncated if a record sample or expansion limit is exhausted; an interrupted scan returns an error. | 2026-10-28 |
| The existing graph port has no way to narrow 15–500 GB cases by Parquet partition. | Add a typed optional graph filter for UTC window, account or project, and region to the port; validate it against case and organization scope before dispatch. Keep unfiltered calls as wrappers around the same implementation. | Arrow scans only selected signed partitions and applies an exact timestamp predicate; filtered queries reject unmigrated legacy data rather than silently mixing incomparable results. | 2026-10-28 |
| Cloud object reads must not silently add a second HTTP stack or a system credential fallback. | Use `object_store` 0.13.2 with explicit secrets from the configured `SecretBackend`, `irmind-http`'s rustls/native-roots connector, HTTPS-only endpoints, and disabled redirects. | The 0.14 line would add reqwest 0.13 and platform-verifier to the current build. Revisit the version when the transport stack can be updated together. S3 ETags are treated as opaque version guards, never as evidence hashes. | 2026-10-29 |
| Cloud providers do not expose a portable checksum through `object_store` 0.13.2. | Sign IRMind's streaming SHA-256 of the downloaded bytes and retain ETag or provider version as an opaque consistency guard; leave a native checksum unavailable when the SDK cannot supply one. | Native provider checksum fields do not strengthen the current custody proof. The analyst accepted this limit for Phase R. | 2026-10-29 |
| A compromised object endpoint can return an oversized listing page before IRMind counts objects. | Pin a local, license-preserving patch of `object_store` 0.13.2 that caps every buffered metadata HTTP response at 8 MiB before parsing. Keep object GETs on the bounded streaming path. | Large or malformed pages fail closed without unbounded accumulation; review the patch when upgrading `object_store` and keep the cap covered by tests. | 2026-10-29 |
| The vendored object-store crate pulled `quick-xml` 0.39.4, which has two new XML parsing advisories. | Raise its compatible dependency to 0.41.0 and keep the existing 8 MiB HTTP body limit. | S3, GCS, and Azure parsing use the fixed XML reader; revisit this pin when updating the vendored crate. | 2026-10-29 |
| Object storage needs a signed prefix boundary without changing existing case scopes or the audit entry layout. | Add `CaseScope` v3 with `objects` entries such as `s3://bucket/prefix/`; keep v1/v2 parsing and all existing audit, seal, and export encodings. An object outside the case or organization prefix is denied. | The TUI and policy TOML can name exact cloud prefixes. Existing signed cases retain their original scope bytes. | 2026-10-29 |
| Remote Parquet conversion must make only one cloud download and must remove intermediate plaintext. | Stream the version-bound object once into a private temporary directory while calculating SHA-256, then convert that spool locally and delete it on every exit path. Require a prior signed, complete listing of the exact object and version. | Transfer size is reserved in the signed audit log before dispatch; failed transfers consume the reservation. The original stays in the cloud unless the analyst separately requests a copy. | 2026-10-29 |
| A system temporary directory may be memory-backed and cannot safely hold a large cloud object. | Add an optional private case spool operation to `LargeCaseStore`, check free space against the signed listing size plus a margin before remote dispatch, and remove orphaned spools when opening a case under the existing case lock. Parse local seekable Parquet directly through a compatible parser method. | Every object source shares the same case-local spool path. The case lock prevents cleanup from racing an active transfer without blocking Windows file reopening. Existing signed manifests, audit events, and seals remain unchanged; cleanup counts go only to diagnostic tracing. | 2026-11-01 |
| Re-reading a cloud original after sealing would create a new verification record without reopening the immutable case chain. | Defer remote re-verification of sealed cases until after the MVP. Keep signed repeat reads for open cases and offline verification of explicitly retained originals after sealing. | The MVP makes no claim about the current state of an uncopied remote original once its case is sealed. A future design may bind a new check to the seal in the separate signed operational chain, but that path is not implemented in R. | 2026-10-29 |
| A sealed legacy case cannot accept derived Parquet records in its immutable case chain. | Record migrated artifacts in the separate signed operational chain, bind each record to the existing seal hash, and carry the complete chain in v4 export. | The historical seal and v3 format do not change; export verification requires every operational signature and artifact link. | 2026-10-28 |
| A crash between signing a source manifest and its derived artifacts would leave an open case structurally inconsistent. | Add `AuditLog::append_batch` and sign the source record and all new artifact records before one SQLite transaction. | Failed inserts roll back the entire file's signed batch; derived Parquet files may remain unreferenced and can be safely retried. | 2026-10-28 |
| Windows reported a generic Parquet ingest failure with no safe diagnostic detail. | Return fixed, phase-specific storage errors for source opening, output preparation, artifact publication, and artifact verification. | CI can locate platform failures without logging paths, file content, or underlying error strings. | 2026-10-28 |
| Concurrent Windows Parquet workers could observe an intermediate DACL while another worker secured the same directory. | Serialize only Windows ACL updates and their verification inside `irmind-fs`; keep parsing and Parquet writing parallel. | A repeated same-content ingest test exercises the race. A poisoned ACL lock fails closed, and no source path or raw OS error enters the application error. | 2026-10-31 |
| Public terminal visuals must never expose a real case or local environment. | Generate README images from an offline synthetic TUI fixture in the official VHS v0.11.0 image pinned by digest. | The renderer, browser, and media tools are fixed together; v0.12.0 is deferred because its canceled render context produced no GIF or PNG in the local probe. | 2026-10-27 |
| Operational timings help diagnose slow remote calls but are not custody evidence. | Write bounded, private `tracing` diagnostics separately from the signed audit chain. Emit only static operation and tool names, outcome categories, and durations; never arguments, case content, endpoints, secrets, or error strings. | Diagnostics are not exported or used by `verify`. The signed log remains the sole record for policy decisions, evidence, approvals, and cancellation. | 2026-10-28 |
| Alert retrieval must retain the single authorized remote-dispatch path agreed for B2. | Model alert retrieval as the scoped `siem_get_alert` tool executed by `SiemPort::execute`. Splunk builds an exact-ID search from the configured index, account field, optional alert ID field, and server-side UTC window. | No second remote execution method or free-form model SPL is introduced. Analysts can request the same tool from the TUI; the policy, evidence store, and audit path remain shared. | 2026-10-28 |
| Large cloud investigations may benefit from querying their source after the local-storage MVP. | [Design a structured `CloudQueryPort`](cloud-query-design.md) now; defer Athena, CloudTrail Lake, Security Lake, BigQuery, Cloud Logging Log Analytics, Azure Data Explorer, and Azure Log Analytics adapters until after the MVP. | No free SQL or KQL from the model. Cost estimation, scan ceilings, explicit approval when estimates are unreliable, and signed result/job IDs are required before implementation. | 2026-10-28 |
| DFIR exports need distinct format detection without changing the signed source manifest. | Keep Velociraptor, Hayabusa, Chainsaw, plaso and EZTools in separate feature-gated parser crates. Decode JSON into typed borrowed fields after bounded shape checks; use the `csv` crate for quoted CSV records with bounded input. Normalize timestamps to UTC and record the normalization context in SourceManifestV2. | The existing parser registry, guard, custody and verification path are reused. The new production `csv` dependency requires explicit maintainer approval before merge. | 2026-11-01 |
| Network logs require cross-file correlation without changing the signed Parquet artifact format. | Add Zeek and Suricata EVE as separate feature-gated parser modules. Index Zeek `uid` and Suricata `flow_id` as bounded local graph entities, retain full fractional source timestamps in original records, and keep the current date/account/region partition layout until a versioned host and microsecond artifact design is approved. | Correlation works through the existing signed graph and parser registry. The current timeline index still has second precision; [issue #143](https://github.com/ns2switch/irmind/issues/143) tracks the format change. Host is queryable as an entity but is not yet a partition key. | 2026-11-01 |

| The demo mixed its current guide step with unrelated status hints. | Keep command instructions in the visible guide; show ingest completion as a fact and omit generic welcome/composer suggestions there. | Ordinary case hints remain unchanged. Guide completion selects the next instruction without adding a competing command to status messages. | 2026-11-02 |

The prompt-injection corpus intentionally contains English and Spanish attack samples. Its rule-set fingerprint can be recorded in signed audit data, so this documentation change does not rewrite those strings. Existing signed event identifiers and serialized formats also remain unchanged.

## Declarative parser definitions (approved)

**Context:** Each analyst-defined format needs a stable identity and exact historical reconstruction without static string leaks or mutable global state.

**Decision:** Add default-compatible borrowed identity methods to the streaming parser port and owned catalog keys. Keep legacy native methods. Sign the full bounded definition in the existing global operation envelope, retain the SHA-256 in the existing source parser-version string, and resolve historical versions from verified signed snapshots. New local compiler/store ports keep parsing pure and storage at the composition boundary. No external package version or signed wire tag changes.

**Consequences:** A declaration cannot outrank a native high-confidence match. Changed or unsigned files stay disabled, and restoration is explicit. A post-signing write failure is recoverable without weakening approval or custody. The reviewed artifact-v2 design remains unimplemented.com/ns2switch/irmind/pull/151).

## Approved precision and EVTX isolation order

**Context:** Parser expansion needs precise timestamps without changing historical JSON normalization through Cargo feature unification.

**Decision:** Approve the revised [artifact-v2 design](parquet-artifact-v2-design.md). First prove JSON map-order independence without changing existing formats or goldens, then deliver syslog/Linux, then implement V2 in separate reviewed steps. Start the host-partition cap at 64; use the 15 GB benchmark to select its default and keep 1,024 as a hard ceiling.

**Consequences:** EVTX follows V2 as the official decoder in an isolated Cargo workspace and bounded, network-disabled subprocess, rather than a fork or a dependency in IRMind's workspace. Helper outputs are untrusted and keep record/offset provenance. Its release binary requires signatures, attestations, checksum, SBOM, an unsafe report and at least one hour of malformed-EVTX fuzzing. Dependency/distribution approval is required before merge. No signed format changes in this documentation PR.

## JSON map-order independence

**Context:** Cargo features can replace serde_json's sorted map with an insertion-ordered map, affecting normalized records, bounded extraction and derived artifact hashes.

**Decision:** Preserve historical bytes with explicit recursive lexical sorting at Value boundaries; keep typed field order, ordered collections and original evidence bytes. Test a frozen pre-change corpus with and without `serde_json/preserve_order` in CI. See [the serialization audit](json-format-order.md).

**Consequences:** No format, tag, signature challenge or existing golden changes. A mismatch requires analyst review. Future parsers follow the same rule; EVTX remains isolated in its separate workspace after artifact V2.

## Syslog streaming and timestamp context

**Context:** Legacy syslog omits year and zone, and gzip support needs a reviewed decoder. Guessing from the machine clock would undermine reconstruction.

**Decision:** Keep syslog in its own optional, default-compiled parser module. Inject explicit year and fixed UTC offset at composition; bind them in the existing parser-version and SourceManifestV2 context fields. Resolve historical versions from those canonical values. Pin 1.1.10 with the miniz_oxide backend and bound input, output, records and samples.

**Consequences:** No new port or signed-format changes. Source precision remains intact; V1 indexing stays second resolution until artifact V2. Invalid gzip is atomic, and parsed content stays tainted. The module does not infer DST or year rollover and does not widen graph-query policy. See the [contract](syslog-parser.md).

## ConPTY screen assertions

**Context:** Windows CI exposed a tutorial PTY timeout while waiting for the next graph instruction. The test searched raw ConPTY bytes, which can repaint only part of a word; the captured console also decoded UTF-8 UI glyphs with its legacy code page. Linux and macOS use a different PTY implementation.

**Decision:** Set UTF-8 only in the test console and reconstruct a bounded current screen for Windows assertions. Wait for the guide's `Do:` instruction, rather than loose command-name fragments. Unit tests cover cursor repaints, chunked UTF-8, titles, erase-character/display commands and stale frames. Custody tests wait for the exact numbered confirmation choices; a previous confirmed finding must not satisfy that wait.

**Consequences:** Tutorial actions, deadlines, cancellation and cleanup assertions remain intact. No production behavior, dependencies, ports, signed formats or security controls change. The test screen handles the English single-cell UI, not arbitrary wide/combining terminal input.

## Per-ingestion source time without a signed-format change

Context: a global RFC 3164 year cannot interpret unrelated files or a year boundary safely. Use two additive optional LogParser capabilities.

Decision: use bounded ParserTimeContext values with a closed Analyst/Command/ConfirmedSuggestion basis. TUI and command ingestion share parser selection and immutable context-specific instances. Only syslog and Linux change parser versions. Suggestions require verified signed same-host records and explicit analyst confirmation. December → January rollover is visible, enabled by default, and per file. Other backward months are rejected. Existing SourceManifestV2 context and parser-version fields bind the inference; signed wire encodings and historical byte/hash goldens do not change.

Consequences: retired global syslog settings need an explicit signed cleanup before cases open. The composition root retains their exact former schema for review only; modules never receive them. Historical v1 source reconstruction retains fixed-year semantics. IANA/DST support remains [issue #161](https://github.com/ns2switch/irmind/issues/161), with no new dependency in this correction. See [design and compatibility flow](syslog-ingest-time-design.md).

## Shared source calendar for Linux and syslog

Context: Linux authentication exports and syslog share the approved RFC 3164 inference rule, while adapters must not depend on one another.

Decision: keep the immutable validated time context and pure candidate calendar in the application. Each module validates its own complete row before committing its local candidate. Detection stays module-owned, bounded and independent of filenames. PRI-prefixed records retain syslog selection. Linux is a default-compiled experimental feature with no new external package, credential or signed wire encoding.

Consequences: historical syslog interpretations and golden bytes stay identical. Linux audit groups retain component offsets and exact argument boundaries; an unproven group stays partial. Journald/audit fractions remain in original/normalized text while artifact V1 indexes seconds. Native host partitioning and indexed subsecond precision follow the approved artifact-V2 design.

## Global card expansion and terminal fallback

Context: Ctrl+O was gated on conversation focus even though the normal focus is the composer. Long notices also rendered only their first line after toggling.
Decision: handle expansion as a global case-screen presentation action before form/menu handlers, use the same operation for `/expand`, and fall back to the last expandable card. Preserve draft, focus, approvals and form state. Show the slash alternative in folded-card hints.
Consequences: no application port, policy, signed format or dependency changes. PTY and TestBackend tests cover the raw key path; GUI terminal, SSH and tmux manual coverage must be reported separately.

## Offline demo as a live presentation

Context: the event-driven tutorial required too many commands and its corner guide hid the next action.
Decision: keep ten bounded scenes in versioned data and execute their commands through the ordinary TUI dispatcher. Use only the isolated demo composition, temporary keys and scripted model. No network probe or real workspace is permitted. Narration remains separate from model context. Actual completion events gate advancement; errors pause visibly. Only demo enrichment and custody previews are confirmed automatically, through their existing signed paths.
Consequences: the large bottom panel reserves a 100 × 40 minimum while visible. Enter/Backspace/Space/Esc navigate presentation state; normal case keys stay unchanged. Revisiting a scene never repeats completed ingestion, approvals or sealing. Expected answers load only for the local check. Existing VHS generates the complete recording without a new dependency.

## Compact presentation at the standard terminal size

Context: a 100 × 40 minimum blocked the demo in standard 80 × 24 terminals.
Decision: support 80 × 24 with a compact lower narration pane, pinned controls and final choices, independent narration scrolling and hidden secondary panels. PgUp/PgDn pauses playback for reading. Confirmation previews use the space above narration. Keep 100 × 40 as a recommendation, with a blocking notice only below 80 × 24.
Consequences: use the same ingestion, policy, signing and custody paths at both sizes. Cross-platform PTYs run the whole presentation at 80 × 24. No point release is required for this layout adjustment.

## Artifact V2 foundation follows the approved envelope

Context: the approved precise-time design introduces new derived schemas and an additive signed envelope; historical V1 bytes must stay reproducible. Decision: define checked integer UTC time, explicit precision/inference, and `ParquetArtifactV2` with the approved seven field groups and strict bounded decoding. The [wire layout and independent golden](parquet-artifact-v2-wire.md) make the field-3 discriminators explicit. Consequences: V1 remains the only production writer until the separate mixed-reader/writer PR; a premature V2 chain fails closed. No production dependency or agreed port changes in this foundation. Host allocation still starts at 64 and awaits the release benchmark before its default is finalized.

## Versioned artifact boundary and precise parser callbacks

Context: the approved artifact V2 cannot pass through a V1-only storage port, and a legacy `GraphRecord` cannot declare exact source precision. Decision: use the documented `ParquetArtifact` sum type at the existing storage boundary and two optional indexed parser callbacks carrying `Tainted<IndexedGraphRecord>`. Keep historical normalized records, parser identities and V1 reconstruction byte for byte; the new builder pins the derived metadata. One checked comparator and numeric inclusive time filter serve mixed queries. Consequences: no dependency or source format change, no duplicate custody path, and no precision loss during compatible compaction. The intermediate V2 writer is explicit until generic partitions and export V5 can be enabled together; default analyst sessions retain exportable V1 cases during these separate implementation PRs. See the [approved contracts and rollout](parquet-v2-port-transition.md).


## Deterministic generic partition preparation

Context: concurrent per-source writers cannot deterministically allocate signed cardinality slots. Decision: use the documented additive batch preparation, parser-owned closed profiles and checked host selectors. Add the already locked `unicode-normalization =0.1.26` directly to infra, derive the policy ID from its declared Unicode version, and pin that version in a test. Stage at most four normalized sources privately after a disk-space preflight; bound writes and report peak temporary storage in the 15 GB benchmark. Consequences: allocations depend only on signed history and canonical source/record order. Invalid host selectors fail closed and cannot exceed either scope ceiling. Historical builders and golden bytes remain unchanged; the TUI keeps V1 writing until generic partitions and migration/export V5 are both integrated. See [approved contracts](parquet-v2-partition-contracts.md).


## Source-bound partition replay

Context: a mixed-source reconstruction router cannot identify a signed parser from a normalized record alone. Decision: use the additive optional `partition_profile_for_source(source, record)` companion. Its default delegates to the approved closed profile; only the signed-source router resolves the source and fails on an unknown source. Consequences: native implementations remain compatible, routing has no mutable last-source state, and storage does not guess a product dialect. Signed formats and historical builder behavior are unchanged.


## Released JSON fast-path reconstruction is lexical (historical through 0.1.5)

Context: parser output must be independent of serde map representation. Published-build feature graphs define the compatibility boundary. [All 23 locked release target graphs](release-json-feature-audit.json) for v0.1.0–v0.1.5 exclude `preserve_order`. In workspace tests, the AWS connector's development-only `aws-smithy-http-client/test-util` enables it; release normal/build edges do not.

Decision: use the release-only compatibility rule. Keep `json-stream-v2`, explicitly sort fast-path maps recursively before extraction and serialization, and reproduce released lexical bytes with either serde map implementation. Do not create an insertion-order reader. Unsupported development cases that depended on insertion ordering fail reconstruction against their signed hashes; never silently rewrite or accept them. Keep the AWS test dependency outside release builds and add a feature-isolation gate before every release build.

Consequences: no signed format, parser identity, existing golden or production dependency changes. Dedicated alternate-feature tests cover every present JSON parser, including NDJSON, single objects and capped extraction. Zeek/Suricata modules are not yet present and gain no claimed coverage. See [release audit and parser coverage](json-line-order-compatibility.md).


## Explicit artifact migration and bounded inventory commitments

Context: precise derived artifacts need an explicit transition that preserves historical custody and remains bounded for large cases. Decision: stage and independently reconstruct replacements in private case-local storage; publish them only with an atomic analyst-signed audit batch. A counted SHA-256 commitment binds every original source, old/new artifact envelope and parser transition within the existing payload ceiling. One pure lineage interpreter selects active generations for application, queries and V5 verification. Retain historical files and reject changed non-time record meaning. Add optional local preparation and V5 export operations with unsupported defaults for existing adapters. Consequences: no production dependency or existing signed encoding changes; V1-only exports retain V3/V4 behavior. The initial rollout held default TUI writing at V1 through migration and release benchmark integration; see the current interactive selection below. See [contracts](parquet-v2-migration-contracts.md) and [analyst guidance](case-migration.md).


## Counted V2 seal inventory and authenticated derived exports

Context: precise cases retain both derived generations, whose metadata belongs to one complete inventory. Decision: use the versioned counted canonical commitment specified in the [migration contract](parquet-v2-migration-contracts.md#bounded-v2-seal-inventory). Recompute it from the authenticated chain; never trust a supplied count or root alone. V5 carries every case-chain derived file in canonical path order and verifies each size and SHA-256 against its signed manifest. Consequences: the 1 MiB metadata-frame ceiling, V1 seal inventory, historical goldens and seal-signature challenge stay unchanged. Tests cover large metadata inventories and real signed packages; canonical/export fuzzing uses AddressSanitizer.


## Current parser identities and reconstruction

Context: parser completeness is part of the derived-evidence contract, independently of source hashing and chain authentication. Decision: new JSON ingestions use `json-stream-v3`. The affected ECS, OCSF, Velociraptor, Hayabusa, Chainsaw, plaso and declarative readers use their next identity. Every new ingestion records that identity explicitly in the existing SourceManifestV2 encoding, including directly configured parsers without detector confidence.

Consequences: do not ship historical parsing implementations or reinterpret their identities as current algorithms. Existing chain authentication, original-byte checks and export verification remain available. Rebuilding with a retired parser fails clearly; create a new case and re-ingest verified originals with current readers. Reinstall declarative definitions to approve the new compiler identity. Historical golden bytes remain unchanged; separate fixtures cover current identities. No signed wire encoding, production dependency or port changes.

## Parser retention policy for 1.0 (pending confirmation)

Context: signed parser identities make reconstruction dependent on the version that produced an artifact. Pre-release reader retirement is not a suitable long-term compatibility promise.

Proposed decision: from 1.0 onward, retain an obsolete parser version for reconstruction and verification for at least two subsequent minor releases, or an equivalent support period. Announce retirement in the changelog before removal and document a migration procedure. Confirm the policy and the meaning of an equivalent support period before 1.0.

Consequences: include the policy in the [1.0 acceptance criteria](roadmap.md#10-criteria). This is a pending compatibility commitment, not an implementation or a restoration of retired pre-1.0 readers. Existing signed bytes and verification rules do not change.

## One PTY backend for integration tests

Context: the Unix test driver used a separate terminal-process dependency chain. The existing Windows driver already uses `portable-pty`.

Decision: use that same pinned development dependency on every supported platform. Keep real terminal input, rendered-screen checks, explicit terminal dimensions, timeout/output bounds, process termination and temporary-data cleanup. Bound the reader queue and share the driver with the first-run regression test.

Consequences: remove the separate `expectrl`, `ptyprocess` and legacy `nix` chain, including its unmaintained `pin-utils` dependency. Do not add an advisory exception. No production dependency, application behavior, signed format or agreed port changes.

## V2 ingestion optimization gates

Context: full-size cloud and endpoint measurements exceed the existing V2 ingestion or query targets. The initial optimization rollout kept V1 as its default writer. Complete every source's parser/hash checks before publishing batch output and account for all retained provisional files. Keep PTY regressions in a bounded interactive test group without changing their action deadlines or serializing the suite. On Windows, reserve the test-thread pool while a ConPTY session runs, so disk-heavy parser and compile-fail suites cannot compete with its custody operations. Other tests retain normal parallel scheduling outside those sessions. See [nextest resource reservations](https://nexte.st/docs/configuration/threads-required/).

Decision: retain 64 ordinary host partition values per case, with a configurable ceiling of 1,024 and signed overflow. Optimize ordered ingestion, disordered runs and bounded queries in separate changes. Compare baseline and candidate release builds on the same runner, with separate chronological and disordered 15 GB endpoint corpora. Keep the 900-second ingestion and existing query limits unchanged.

Consequences: the direct-write path assigns partitions in deterministic source order through bounded parser queues. Its Parquet files and allocator changes remain provisional until the complete source is verified. Disorder stops speculative parsing at the first decreasing batch, discards provisional files and allocations, and uses the existing verified spool/sort path. Retain the original hash/metadata snapshot for the full fallback parse; never publish an incomplete parse report or swallow real cancellation. Detect decreasing keys in the producer before queueing them, retain the existing bounded 8 MiB handoffs for ordered throughput, and recheck order in the deterministic coordinator. Each worker prepares its own authenticated fallback spool, so disordered sources retain parallel parsing before deterministic sorting and allocation. Historical builder identities, signed formats and reconstruction bytes remain unchanged. V2 activation requires the cloud and chronological corpus targets to pass; report the disordered corpus independently against the same ingestion target.

## Bounded natural-run ordering for V2

Context: endpoint exports can contain a small number of monotonic timestamp runs. Repeated full chunk sorting and pairwise merges add work without changing the required stable order.

Decision: split the verified normalized spool into at most 32 existing monotonic runs and merge them with the shared stable comparator. Limit combined merge-head storage to the existing batch memory budget. If either bound is exceeded, discard those temporary runs and use the existing external stable sort. Reuse each already-canonical encoded record during splitting and merging, rather than serializing it again. Account for both parsed merge heads and retained byte buffers. Check cancellation and authenticate each run's size, count and hash before publication.

Consequences: preserve the normalized byte stream and all resulting Parquet hashes, signed envelopes and reconstruction rules. Compare natural-run output with the original external sorter, including a source that exceeds the run limit. Release benchmarks remain paired against the preceding optimization on the same runner; the 900-second and query acceptance limits do not change.

## Authenticated time bounds for global timelines

Context: a date partition can contain many files, so reading every event in that date can exhaust the existing query deadline even for a short timeline.

Decision: obtain conservative per-file extrema from existing Parquet statistics only after checking the complete file against its signed hash. Order candidate files by those bounds and stop only when the retained cutoff is strictly better than every remaining bound. Equal instants retain the shared stable source/offset ordering. For legacy whole-second ties, authenticate existing source/index statistics; if a group contains multiple sources, project only its reference columns to derive a conservative stable-key bound. Prune a tied group only when that bound is strictly worse than the retained result. Missing or inexact time statistics cannot prune a file. Reauthenticate each file when scanning its projected columns.

Consequences: support legacy and precise artifacts without new signed metadata, schema or port changes. Keep the existing result/deadline limits and cancellation; metadata discovery shares that same deadline. Internal ordering supports both directions, while the public timeline keeps its existing most-recent-first behavior. Tests compare bounded results with complete mixed-generation scans, including submicrosecond ties and unknown times.

## Measure event-reference co-observations before a schema decision

Context: precise co-observations repeat time/order columns even though they already carry a source hash and record index. Removing those columns would trade disk space for additional event-reference resolution during time-filtered queries.

Decision: measure the compressed bytes of those columns separately in release benchmarks and publish a [design proposal](coobservation-reference-proposal.md). Do not modify the approved V2 schema, builder identity, signed encoding or reconstruction algorithm in this measurement change.

Consequences: any production implementation remains a separate compatibility decision with measured disk and latency results. Existing hash checks, time filters, bounded-query behavior and historical verification remain unchanged. The measured four-column payload is about 0.56% of cloud co-observation storage, 12.7% in disordered endpoints and 39.4% in chronological endpoints. Evaluate a new reference-only schema for endpoint storage separately; this stack retains the current schema and does not claim an achieved size saving or a free reference join.

## Borrow batch-lifetime keys for entity extrema

Context: precise entity queries need exact counts and earliest/latest records, not a rendered timestamp for every matching row. Formatting every timestamp and allocating source/hash ordering keys adds work that legacy second-resolution queries avoid.

Decision: retain physical precise timestamps during count/extrema scans, compare borrowed source/hash keys with the existing stable comparator, and allocate at most two retained extrema per batch. Cache only the immediately preceding validated source binding inside each immutable Arrow batch; every changed hash is checked against the signed source set and mapped again. Null record indexes remain errors on every row. Render their timestamps once when producing the final result. Other query projections keep their displayed timestamps. Record separate verification, scan, normalization and aggregation timers in paired release measurements.

Consequences: preserve exact mixed-generation, pre-epoch and submicrosecond ordering, unknown-time counts, source membership validation and hash checks. No schema, signed encoding, port or default-writer change. Query phase timers overlap the scan pipeline and must not be summed as wall-clock percentages. In the matched cloud V2 profile, entity p95 falls from 8.712 to 4.580 seconds while hash-verification work remains essentially unchanged.

## Select V2 in the interactive composition root

Context: the [complete optimized release matrix](benchmarks.md#final-v2-ingestion-and-query-gate) meets the approved cloud and chronological ingestion/query gate. The disordered control still exceeds 900 seconds and remains separately tracked.

Decision: construct the existing precise store for TUI and offline-demo sessions. Retain the current automation construction and explicit migration path. Keep existing case history and V1 readers; use the existing automatic V5 export selection for cases containing V2 artifacts.

Consequences: the default is 64 ordinary hosts with a hard ceiling of 1,024 and signed overflow. This selection changes no port, dependency, wire encoding or existing artifact. A same-source artifact-version replacement still requires explicit migration. Retain all measured failures and continue the disordered-ingestion work against 900 seconds.


## Analyst-approved release and disordered-stress gates

Context: the final paired release measurements convert 15 GB of cloud logs in 865.973 seconds and chronological endpoint logs in 488.131–561.596 seconds. Disordered endpoint controls take 1,007.507–1,120.179 seconds, with all sampled candidate queries meeting the existing targets.

Decision (analyst): the v0.2.0 release gate remains strictly below 900 seconds for cloud and chronological endpoint ingestion. Treat disordered endpoint ingestion as a stress workload with a strict 1,350-second gate (1.5 times the release limit). Existing query targets, hash verification, budgets and truncation semantics do not change. This supersedes the earlier 900-second disordered acceptance decision; preserve historical measurements and workflow conclusions.

Consequences: the measured candidate meets both workload gates. [Direct merge-to-writer optimization](https://github.com/ns2switch/irmind/issues/186) and reference-only co-observations are post-v0.2.0 work. The cloud `co_entities` column payload is about 4.04 GB and is a separate disk-size concern; see [the measured reference proposal](coobservation-reference-proposal.md) and [issue #37](https://github.com/ns2switch/irmind/issues/37).

## One V2 ingestion default for every presentation

Context: CLI automation, TUI and offline demo invoke the same ingestion use cases. Maintaining different default writers has no remaining compatibility or performance justification.

Decision: all production composition paths select the existing precise V2 writer, including CLI ingestion. An explicit legacy constructor remains available for historical fixtures and compatibility tests, not as a presentation-specific default.

Consequences: opening any V1 case never migrates its signed artifacts or history. New V2 sources may coexist with V1; replacing an already-indexed source still requires optional, attended, verified migration. Export selects V5 when required. Existing ports, signed encodings, parser identities and goldens remain unchanged. After step (e), the v0.2.0 order is the isolated EVTX helper, experimental Elastic and Chronicle, then release notes, optional-migration guidance and the existing signed distribution workflow.


## One native Windows boundary for EVTX containment

Context: EVTX decoding must run in an isolated subprocess, while the existing filesystem helper already contains reviewed Win32 ACL and durable-write calls. A single source-policy gate must cover both uses.

Decision: consolidate first-party unsafe code in irmind-process-containment, compiled only on Windows and using Microsoft's windows-sys. Keep a safe public API, deny unsafe_op_in_unsafe_fn and undocumented_unsafe_blocks, and document every minimal block's SAFETY invariants. Move the existing ACL/durable-write implementation without changing irmind-fs callers or guarantees. Domain, application, TUI, main executable and parser forbid unsafe. Non-Windows containment code also forbids it.

Consequences: the direct Windows process/security APIs have unsafe signatures because Rust cannot validate their pointer lifetimes, buffer layouts and handle ownership. No standard-library safe API provides AppContainer plus explicit inherited handles and suspended Job Object assignment. Keep these invariants in one reviewed boundary, rather than exposing raw handles or hiding calls in parsing/protocol code. CI rejects unsafe elsewhere. Native containment tests remain required before integration.

## Unprivileged Linux EVTX containment

Decision: use maintained safe Landlock and seccomp APIs in the single-threaded helper before decoding. Require fully enforced Landlock ABI 1 filesystem denial and no_new_privs, plus a fail-closed seccomp allowlist that excludes sockets, execution, process creation, io_uring, truncation and access to unrelated descriptors. ABI 1 requires Linux 5.13 or newer with Landlock enabled; newer unhandled filesystem operations remain denied by seccomp. Missing support is module unavailability, never a downgraded sandbox. Bubblewrap is optional and not a requirement. macOS retains the tested deny-default sandbox-exec profile; unsupported versions fail closed. See [the containment design](evtx-helper-design.md).


## EVTX native loader and audit boundaries

Context: the decoder runs under a deny-default OS policy before reading evidence. Native loaders also need their own narrowly identified runtime resources.

Decision: macOS permits read/map access to the OS Cryptex runtime paths, the system library paths, the exact helper and root-directory reads. It retains filesystem write, network and fork denial. Windows creates a unique zero-capability AppContainer profile, restricts its fresh filesystem tree to owner access and package read/execute before launch, and deletes the profile when its child runtime is dropped. The environment contains only the OS-reported SystemRoot and LocalAppData paths required to establish the runtime and AppContainer namespace; it does not inherit process variables or credentials. Read/execute grants remain limited to the helper and its private launch directory.

Consequences: native launch and denial probes must pass together. A failed profile creation, loader startup or enforcement probe leaves EVTX unavailable. The release audit uses pinned prebuilt cargo-geiger 0.13.0 with source compilation disabled, verifies its executable digest, and publishes path-free AST metrics alongside the supplementary source inventory. Neither report is a memory-safety proof; macro expansion and platform coverage limits remain explicit.


## Separate broker and decoder native imports

Context: a Windows decoder runs inside an AppContainer, including on non-interactive hosts. Parent-side profile and known-folder APIs can introduce DLL initialization requirements that the decoder does not need.

Decision: the containment crate keeps its safe broker API behind a default `launcher` feature. The independent decoder disables that feature and retains mandatory token/enforcement checks. Derive LocalAppData from the OS-created profile's validated Packages layout, avoiding Shell API imports. Integration tests build and preserve the normal decoder before resolving their parent harness's development features, execute that same production-feature binary under the native policy, and restore it for the main CLI tests.

Consequences: keep a single first-party unsafe crate and unchanged source/protocol formats. Test-only dependency unification cannot determine the shipped decoder's native imports. CI retains launch, handle, network, file-access and termination assertions and prints imported DLL names when native startup fails.


## Read-only AppContainer runtime profile

Context: Windows creates private per-container runtime metadata as part of its profile. That fresh profile is distinct from case storage, evidence and analyst credentials.

Decision: retain package read/execute access to the bounded OS-created profile tree while replacing its package-write grants. Keep owner-only case data and canary files, the explicit input/output handle list, zero network capabilities and the suspended Job Object start. Validate the profile layout before deriving its LocalAppData root; delete the profile after the child ends.

Consequences: runtime initialization can read its own isolated metadata. The decoder receives no write access to that tree and no grants on the surrounding LocalAppData directory, user configuration, keys or evidence paths. Native denial tests remain mandatory.


## Pipe-only Windows decoder startup

Context: the decoder has no interactive console and communicates through the explicit inherited evidence/stdout/stderr handles. Allocating a windowless console is unnecessary for this protocol and introduces additional runtime process requirements.

Decision: start the suspended Windows decoder with DETACHED_PROCESS rather than CREATE_NO_WINDOW. Keep the explicit three-handle list, zero-capability AppContainer, child-process restriction, one-process Job Object, memory limit and pre-decode enforcement probes unchanged. This is console detachment, not Job Object breakaway.

Consequences: no console host is requested by the launcher. Native decoder, denial, handle-inheritance and termination tests still determine availability; a successful cross-compilation cannot establish that the loader starts.


## Distinguish the Windows runtime directory from inherited evidence

Context: Windows supplies a current-directory handle as part of process initialization, independently of the explicit inherited standard-handle list. Rejecting every additional disk handle also rejects that expected OS runtime handle.

Decision: retain rejection of all additional inheritable handles and unrelated disk handles. Recognize only non-inheritable, read-only aliases whose volume/file identity equals the explicitly selected private runtime directory or the inherited evidence. The directory's existing read/execute ACL is unchanged; evidence aliases cannot grant access to another file. For traversal-only current-directory handles, which may not support file-information queries, compare the exact counted NT opened name with the retained private directory's name. This performs no path open and never publishes the name. Reject reparse points, different files/directories and every write right. Query the official windows-sys object/file APIs inside the same dedicated Windows boundary.

Consequences: the three-handle inheritance list is unchanged. Native tests cover exact-directory and read-only evidence aliases, foreign directory/file rejection, write-access rejection and exclusion of an unrelated inheritable file and pipes. The helper receives no additional evidence-path or credential access.


## Typed Windows handle enumeration

Context: runtime handle values are not a contiguous public table. File queries on guessed numeric handles cannot distinguish loader/synchronization objects reliably.

Decision: enumerate a bounded process snapshot using Microsoft's Pss APIs, requesting only handle values. Query each still-live handle's bounded type name before any file query; do not require optional Pss metadata that Windows does not populate for every object. An explicitly closed handle has no usable capability and is ignored; other query errors fail closed. Limit the initial and walked handle count to 512; reject missing type information and failed snapshots. Never request a memory clone, breakaway or new process. The explicit inherited handle list and exact-runtime-directory checks remain mandatory.

Consequences: native handle exclusion tests inspect actual handles without a low numeric-range assumption. Keep every pointer borrow within the live snapshot/walk-marker scope; expose only a safe internal visitor and preserve the single Windows unsafe boundary.


## Session-scoped Windows EVTX traffic witness

Context: Windows WFP filters traffic rather than necessarily rejecting socket creation or returning an immediate permission error. Repeating a full flow test for every small file would impose unnecessary collection overhead.

Decision: retain the zero-capability AppContainer and verify live IPv4/IPv6 endpoints in both directions with positive controls and nonce-bound acknowledgement. A timeout alone is insufficient. Cache the successful witness only in memory, tied to a retained profile and immutable three-role handle policy. Serialize decoders sharing that SID; cancellation remains available while waiting. Subscribe to BFE/MpsSvc status notifications and check Running state, service process IDs and generation before launch and after completion. Any change or validation failure invalidates the cache.

Consequences: ordinary files pay launch checks rather than repeated network witnesses. Read-only private runtime tickets contain no evidence, credentials or persisted witness result. Signed custody encodings do not change. Windows remains experimental pending client validation; native tests and the signed distribution dry run gate integration. See [the network witness design](evtx-windows-network-probe.md).

The monitor establishes a stable initial service snapshot before any witness result can exist. A change during the witness requires a complete retry, bounded to three attempts. Successful reader cleanup does not count as cancellation. Inbound endpoint liveness is checked independently through the bounded OS TCP listener tables for the exact child PID and ports; no host table is logged.


## Linux x86-64 distribution ABI baseline

Context: a helper compiled on a newer Linux userspace can require a libc version unavailable on an older supported system, even when native isolation passes on the build host.

Decision: build and test Linux x86-64 on Ubuntu 22.04. Native Ubuntu 22.04 and Ubuntu 24.04 compatibility jobs execute the same produced helper, including the pinned Debian/Fedora container probes. Release compatibility uses the exact release helper rather than rebuilding it on the test host. Cache keys distinguish this build baseline.

Consequences: distribution checks test one portable artifact across userspaces instead of mistaking a newer loader ABI requirement for an isolation failure. No sandbox probe or enforcement requirement is removed. ARM64 retains its separate native runner and requires separate compatibility evidence.

## EVTX source scheduling and record budget

Context: parsers can have different native concurrency contracts, while case publication must remain deterministic and resource-bounded.

Decision: an optional closed `SourceParallelism` capability defaults to `Concurrent`. EVTX declares `Serial` on Windows. Initial source hashes remain parallel; serial parse-start permits follow canonical source order. Bounded queues and start waits check cancellation. An independent supervisor enforces the auxiliary deadline even while the record consumer waits.

The per-file record ceiling is 8,000,000 in both the decoder and the protocol validator. The 4 GiB source ceiling, 4 MiB frame ceiling, existing output budget and 600-second invocation deadline remain unchanged. A limit rejects the complete file with its value in the diagnostic. Native containment, witness verification, signed ordering and custody formats do not change.

Consequences: Windows can process a multi-file request with one verified session without adding native capabilities. Independent concurrent AppContainers remain [separate work](https://github.com/ns2switch/irmind/issues/191). Release measurements and their scope are recorded in [benchmarks](benchmarks.md#large-security-evtx-collections).

The complete ingestion host's memory is not constant in the dense-source measurements. Bounded-metadata writer work is separate from the EVTX scheduling and record-budget change and requires its own reviewed builder contract. See the [design](parquet-bounded-metadata-design.md) and [native release measurements](benchmarks.md#native-scheduling-and-eight-million-record-results). No existing signed builder is changed by this work.

## Common event schema delivery

Historical planning entry: the independent mapping and layout decision below supersedes the proposed V2 embedding and native-only mapping boundary.

Context: parsers need one validated classification and role contract before additional SIEM mappings. Decision: deliver the approved ECS 9.5-derived common schema as a reviewed core, initial native mappings and community mapping follow-ups; defer CommonEventMigrationV1. Consequences: new physical schema IDs are explicitly supported inside V2; old cases remain readable and never migrate on open. Re-ingestion into a new case is available. Smoke benchmarks use three 1 GiB repetitions; the full 15 GB matrix uses one repetition. Elastic and Chronicle follow the core. Skills, subagents and later releases shift to the public roadmap's new numbering.

## Preserve unmerged parser work

Before deleting a branch, confirm that its PR is merged and check its ancestry with Git’s merge-base ancestor check. An open or closed-unmerged PR is not grounds for deletion. If rebasing changed commit identities and ancestry is not established, retain the branch until its integration can be reconciled; never discard unmerged work silently.


## Typed common-event core and staged mappings

Historical prototype entry: the independent mapping and layout decision below replaces the parser bridge and V2/V5 publication path with mapped V3/V6. The unpublished prototype was never a default writer.

**Context:** Cross-source investigations need explicit classifications and entity roles without changing historical interpretation.

**Decision:** Freeze `irmind-common-event-v1` codes in goldens; use checked domain types and new physical schema IDs inside the existing V2 envelope. A closed, validated field map represents sparse context. An additive parser bridge emits unclassified events until a module has a reviewed mapping. Scoped identities distinguish PID reuse and account/host namespaces. Event role membership is a typed event column; peer descriptors retain scope, field and role.

**Consequences:** Historical builders and goldens stay intact. Existing tools gain closed category/type/outcome/role filters and report schema coverage. Semantic migration is deferred; existing cases can be read without migration and re-ingested into a new case for new interpretation. The separate writer-metadata proposal remains independent. See [the implementation contract](common-event-core.md).

V5 common-schema validation reads each authenticated frame through a range-limited Parquet reader rather than extracting another evidence file. `bytes` is a direct infrastructure dependency for Parquet's `ChunkReader` return type; the same package and features were already present in the lockfile. Existing frame encodings remain unchanged.

## Sparse peers in the new common schemas

Context: the initial common bridge repeats role-free peers in two columns and misses the existing performance gates. Decision: retain legacy pairs in `co_entities`, write only typed descriptors in `co_observations`, and merge them without inventing roles or identity scopes. Complete descriptor lists remain readable; invalid descriptors cannot trigger fallback. Only the new common co-observation physical goldens change. Historical artifacts, logical common JSON, code tables, V2 envelopes, seals and V5 frames remain unchanged. The analyst approved this representation and the direct, already locked `bytes` dependency. The [complete release remeasurement](benchmarks.md#common-schema-core-sparse-peer-matrix) still misses the unchanged ingestion and entity-query gates, so the common writer remains opt-in. See the [design and measured duplication](common-event-peer-layout.md).


## Independent mapping and layout custody

Context: forensic interpretation must evolve independently of source framing, and physical compaction must preserve its original commitments.

Decision: replace the unpublished parser bridge with `SourceDecoder` and pure `SourceMapper` modules. Signed source sets, mapping snapshots/profiles and complete mapping receipts bind V3 outputs. The table interpreter accepts only closed, bounded primitives. Analyst-signed global operations authorize installed definitions; overlap preflight precedes any operation, and exact historical authorizations remain available for replay. Full canonical definition content lives in immutable signed operations, with no unsigned loose file used as an authority.

Consequences: historical parser routes, V1/V2 bytes, seal inventory V2 and export V5 stay unchanged. New export V6 carries required installation proof frames, all retained parents/children and receipts; authentication executes no downloaded mapping code. `ParquetLayoutV1` binds compatible physical replacements without replacing mapping receipts. Inactive-parent disk is measured separately in every 15 GB release benchmark. Any future parent retirement needs a separate reviewed contract. No common writer is enabled by default while its acceptance gates are unmet.

Measured mapped-parent retention exceeds the planning threshold in every 15 GB workload. Preserve all parent files in the current implementation; the separate [retirement proposal](mapped-parent-retirement-design.md) requires an explicit future contract and makes the unavailable direct file authentication clear. The [complete measurements](benchmarks.md#source-decoding-mapped-v3-and-retained-layout-parents) keep the common writer opt-in because its gates remain unmet.

## Historical analyst decision: common-writer default activation

The revised activation decision below supersedes these original gates.

The absolute ingestion targets remain 900 seconds for 15 GB of cloud or chronological endpoint input and 1,350 seconds for stress input. No query may reach its deadline, including the expansive-path check; a time-truncated response does not satisfy this condition. Existing result, sample, hop, expansion, token and scope limits stay unchanged.

Each candidate/reference pair must run in the same release job on the same corpus. Every candidate scenario must take at most 1.10 times its reference ingestion time, and every comparable query p95 must be at most 1.10 times the reference p95. Evaluate the ratios from unrounded timings; rounding cannot turn a failure into a pass.

Default activation requires the relative gate and no query deadline in every scenario. It also requires the absolute gate unless that same scenario's reference misses its absolute target in that same job. Only then can the paired relative gate substitute for the absolute gate. A reference timeout never permits a candidate timeout. Previous combined benchmark pass counts did not evaluate this new relative gate and cannot authorize default activation.

The work order is direct final-file writing, dense entity lookup, then a separate default-activation PR after the complete matrix meets these conditions. Initial direct ingestion must leave zero inactive parents. Later compatible small-file compaction remains available behind a configured count threshold; signed parent retirement remains a [separate future proposal](mapped-parent-retirement-design.md).

Inactive-parent retirement remains a design-only future operation. No parent files are removed by this implementation.

## Direct mapped ingestion and source failures

Context: initial mapped ingestion should create final files without retaining
intermediate Parquet parents.

Decision: use the optional local preparation contract and
`parquet-builder-common-event-direct-v1`. The application signs each complete
bounded group atomically. Source failures roll the group back and exclude at most
16 failed sources before a bounded retry; operational failures abort. Successful
sources refill canonical groups, so rejection does not change the derived bytes
or mapping commitments of the clean collection. The experimental writer remains
opt-in; V1/V2 formats and default selection do not change.

Consequences: rejections use typed payloads in the existing generic tool-error
kind, and displayed paths and samples pass through the guard. The recorded recipe
selects exact reconstruction. Later compaction remains separate maintenance;
initial ingestion retains no inactive parents. Absolute and same-run relative
activation criteria continue to apply.

## Dense query column binding

Context: mapped entity scans repeatedly formatted display timestamps and resolved
ordering columns for each observation.

Decision: bind typed ordering columns once per batch. Materialize text timestamps
only for event output; preserve whole-batch temporal validation, source-unit
checks, signed source membership and per-file hash verification. Instrument scoped
aggregation separately without treating an absent counter as zero work.

Consequences: result, sample, scope, role, hop, expansion and deadline limits are
unchanged. The [exploratory release smoke](benchmarks.md#dense-mapped-entity-lookup-exploratory-release-smoke)
is preliminary; full paired 15 GB measurements remain necessary.

## Analyst decision: revised V3 activation evidence

Context: percentage-only query comparisons magnify subsecond differences, and the deliberately expansive cloud path produces a valid partial result in both implementations.

Decision: a query fails the same-job relative gate only when its p95 exceeds the V2 reference by **both more than 10% and more than 0.25 seconds**. Compare exact nanoseconds; equality at either boundary passes. Every ordinary query must still finish without an error or a time-budget truncation, and below the existing ten-second deadline. The deliberate worst-path check is exempt from the deadline gate only when both V2 and V3 return without errors, both report time-budget truncation, and both retain the explicit partial-result marker. Keep publishing that measurement.

Cloud and chronological endpoint ingestion require both the 900-second absolute target and the same-job +10% ingestion bound. Disordered stress ingestion requires the 1,350-second absolute target; its relative difference remains reported performance work rather than an activation condition. No scope, result, sample, hop, expansion, token, custody or production query limit changes.

Consequences: reevaluate the frozen dense-reader matrix without changing its raw records, then run a fresh paired release matrix on main with the updated SQLite composition. Historical worst-path metric records are emitted only after a successful result unwrap, so their presence records success; missing or contradictory partial-result markers are invalid evidence. A false gate leaves V3 opt-in. A successful gate permits preparing a separate default-selection PR for CLI, TUI and demo, which remains unmerged for review. Mapping families can be delivered independently using optional V3.

## CloudTrail mapping and a shared table interpreter

Context: mapping families must reuse the bounded interpreter without an adapter-to-adapter dependency, and their selectors must not compete with extraction-only JSON compatibility.

Decision: extract the interpreter into the shared `irmind-mapping-tables` utility, retaining the existing module crate as an API facade. The dependency-direction test permits inbound use of that utility but still rejects its dependency on any parser or mapper adapter. Optional primary conditions reuse the existing closed predicates; absent conditions serialize exactly as before, with a regression pin for the historical definition digest.

CloudTrail is a feature-gated mapping module with a bundled, pinned TOML definition. Its primary selector requires the original `eventVersion` field. In a catalog containing that module, the generic extraction mapping explicitly requires the field to be missing and receives a distinct version identity. A null field remains unclassified. Broad compatibility construction remains unchanged for the frozen benchmark route. No parser output, signed wire encoding, scope or approval rule changes.

The new definitions explicitly select `irmind-mapping-tables-v2`: primary conditions reuse the existing finite predicates and the original action is also used for timeline display. V1 definitions retain their canonical bytes and their historical empty display projection. The existing signed interpreter field identifies each version; no envelope, source manifest, seal or export encoding changes. Unknown interpreter versions and mismatches between definition and provenance fail closed.

## Exact absent-value markers in the current table interpreter

Context: documented empty PAM identities and Windows `-` address markers are original source values, but cannot become typed identities or IP addresses.

Decision: implement `omit_text` in the current interpreter without creating another interpreter version. Each field accepts up to eight unique, control-free literals of at most 256 UTF-8 bytes. Only an exact original text match omits that field and its observation; original records and unrelated projections remain intact. Count literal comparisons in the existing operation budget.

Consequences: arbitrary invalid IPs, ports, hashes and scalar types still fail the normal validated boundary. No trimming, Unicode folding, coercion or general error suppression is added. Empty lists serialize as absence, preserving current definition goldens. Retired interpreter removal follows the pre-1.0 cleanup policy.

## Analyst decision: absolute goals for the sole V3 writer

Mapped V3 is the sole target writer. Remove relative ingestion/query comparisons and the requirement for a comparison reader from performance evaluation. Keep all ordinary query error, exact-duration, full-corpus coverage and ten-second checks. Keep 900-second cloud/chronological goals and 1,350-second disordered goals. The 1,025-host disordered sample is a reported, nonblocking goal miss tracked by #218; it does not waive ordinary query limits or the chronological 1,025-host goal.

A deliberate expansive path may report a successful time-budget truncation only with its explicit partial marker. Its error outcome remains a failure. Current measurements identify one mapped writer and nine complete scenarios; missing outcomes, incomplete query coverage or noninteger exact durations are invalid evidence. Historical comparisons remain diagnostic records only.

## Linux source decoding and independent mapping modules

Decode auth.log/secure, auditd, journald and HTTP framing through one `LinuxSourceDecoder`, preserving original names, values, exact time, grouped-member locations and confirmed classic-syslog context. Replace the narrower journald decoder rather than retaining a redundant historical route under the pre-1.0 policy. Keep journald's established extraction projection.

Use separate hash-pinned table modules for sshd, sudo, su and HTTP; each owns one declared SourceMapper port. Use native auditd mapping only for bounded cross-member selection that finite tables cannot express. Do not infer success for missing status, partial audit groups or sudo command requests, or invent process-lifetime identities from reused PIDs. Source decoding remains independent of these interpretations. No production dependency package is added.

## Shared bounded JSON framing for source decoders

Move the existing original-byte JSON framing into the source-mapping JSON utility, so format modules can reuse it without depending on another parser adapter. Framing exposes bounded original bytes and byte offsets; each module still owns detection, format decoding, timestamp interpretation and its stricter limits. SourceRecords stay tainted and mappings remain separate. This move preserves parser-json output and its existing limits byte for byte, adds no dependency, and extends the existing JSON fuzz target to cover the source decoder as well as the temporary legacy path.
## Bounded result materialization for timeline and search

Context: event queries previously formatted an RFC 3339 timestamp and allocated owned event/source strings for every matching row before retaining the bounded result set.

Decision: validate every row as before, rank borrowed ordering keys within each bounded Arrow batch, apply the existing stable comparator and adjacent identity deduplication, and materialize only retained output rows. Keep whole-batch precision and source-unit validation, authenticated file reads, cancellation, deadlines and result limits.

Consequences: this changes query allocation only. It changes no writer, signed bytes, schema, mapping, query order or displayed result. Paired release measurements compare V2, the preceding V3 reader and the candidate on the same runner.


## Approved declarative source pipelines and process-lifetime identities

Compile each parser definition once into a checked selector, source decoder and extraction mapper. Bind all three identities and the fixed extraction descriptor to the exact definition digest. Only application-validated signed installations produce registration tokens; preview uses the same decoder and mapper. Original typed source fields remain separate from the unclassified search/entity projection. No external package or signed envelope changes.

Extend the current table interpreter with explicit, bounded host and lifetime paths for process observations only. Included mappings may use a documented producer lifetime identifier such as Sysmon ProcessGuid. Security 4688, auditd and Linux process observations remain source-record scoped; PID, process name and timestamp never substitute for a lifetime identifier. Invalid or missing scope values fail without falling back to a broader identity.

### Exact declarative reconstruction from approved snapshots

Context: replacing or deactivating a parser definition changes the active source
catalog, while an existing mapped case still pins its original definition and
mapping snapshot.

Decision: full reconstruction resolves that exact pipeline lazily from the
already authenticated global installation history and the current compiled
interpreter. The complete mapping reference must match. Definition contents are
shared in memory; reconstruction does not reactivate them for new ingestions or
load implementations supplied by a case or export.

Consequences: replacement and deactivation preserve reconstruction with the same
creating implementation. Unavailable interpreters and mismatched snapshots fail
closed. Signed formats, limits and authentication-only verification are unchanged.

### ECS interpretation remains a separate native mapping

Context: ECS source fields can be nested or dotted and categorization is a bounded
set. Typed values and occurrence roles require validation beyond finite tables.

Decision: `parser-ecs` only decodes original source fields, instants and provenance.
A separate optional `mapping-ecs` crate handles the agreed ECS 9.5 common subset,
explicit roles and the extraction projection. Shared typed conversion code is
included in its native implementation manifest. PIDs remain source-record scoped.

Consequences: existing search aliases remain available during the optional common
writer rollout. Unknown labels are diagnostic, missing outcome stays unknown, and
conflicting aliases never silently override each other. No new external package,
case envelope or export format is introduced.

### EVTX interpretation is bundled declarative data

Context: binary decoding and event interpretation must remain separate modules.
Decision: reuse the isolated EVTX helper through `evtx-source-v1` and register
hash-pinned table modules by exact provider/channel and original Security EventID. Only Sysmon's reported
process GUIDs establish lifetimes; Security PIDs retain source-record scope.
Consequences: new ingestions can opt into common-event mappings without changing
the existing writer, helper protocol, isolation, custody formats or dependencies.

### Shared source-pipeline allocation and serialization work

Context: standalone decoder diagnostics do not measure the full ingestion path.
Decision: use complete synthetic release ingestions with real custody and separate
Heaptrack allocation-call runs for EVTX, ECS, CloudTrail and Linux journald.
Keep inclusive timing intervals explicit and publish only aggregated profiles.

The common implementation reuses checked JSON serialization, moves owned pure
projections where possible, writes JSON strings into one shared buffer, and uses a
64 KiB buffered reader with a reusable tuple buffer for commitment finalization.
Source hashes remain bound to frozen metadata. No check, limit, taint, canonical
ordering rule, port signature or current format golden is removed or changed.
The profiler and its allocator interception remain development tools; the product
uses its existing allocator and introduces no unsafe code.

### Native OCSF mapping and direct source decoding

Context: OCSF JSON and Parquet require the same typed source pipeline as other
parsers. Classification belongs to an independent, versioned mapping.

Decision: `ocsf-source-v1` retains original fields and timestamp precision;
Parquet uses the authenticated source handle and a row ordinal. Native
`mapping-ocsf` pins OCSF 1.4.0 to validate class/category pairs, nested typed
values, explicit statuses and occurrence roles. Other versions retain
unclassified extraction. No message-text inference or process lifetime from
a PID is permitted.

Consequences: current default ingestion and current golden bytes are unchanged.
The experimental pipeline uses the existing mapping, custody and export
contracts. No production package is added to the lockfile.

### Decode original DFIR fields before unclassified extraction

Context: the common writer must retain the search behavior of DFIR tool output
before the presentation-oriented parser route can be retired.

Decision: use source-only decoders and separately identified native extraction
modules for Velociraptor, Hayabusa, Chainsaw, plaso and EZTools. They retain
original types, exact timestamps and measured record locations. Shared framing
mechanics enforce the existing limits and never downgrade callback failures to
rejected source rows. Tool-specific aliases and relations remain unclassified;
a rule name does not become an analyst-confirmed finding.

Consequences: mappings can evolve independently of format decoding. No signed
format, permission, default model or external production dependency changes.

### Decode syslog headers independently of extraction

Context: syslog must keep the same confirmed calendar and searchable header
identities when the common writer becomes the only ingestion route.

Decision: `syslog-source-v1` decodes original RFC headers and messages, while a
separate extraction-only module retains host, application, PID, facility and
severity aliases. Gzip stays bounded and records no invented compressed offset.
No category, outcome or role is inferred from application or message text.

Consequences: the source selection still signs per-ingestion year, offset and
rollover context. Ingestion and reconstruction use the same source decoder and
mapping. No current signed format or external production dependency changes.

### Preserve original network records before extraction

Context: the common writer needs Zeek and Suricata source decoders before the
presentation-oriented parser route can be retired.

Decision: decode original JSON fields or TSV columns with declared types and
measured offsets. Separate native extraction modules retain existing UID/flow
relations and search identities without interpreting outcomes or entity roles.
The native projections handle literal dotted columns, nil markers and
source-specific relations; no arbitrary expressions or code are loaded.

Consequences: exact decimal timestamps remain available to the common writer,
and reconstruction uses the same signed source and mapping identities. No
current signed format or external production dependency changes.

### Size local worker pools without changing signed groups

Context: a fixed four-source schedule can oversubscribe a small machine and leave capacity idle on a larger one.

Decision: the direct mapped writer and parallel Parquet scans use the available logical CPU count minus one by default. A signed local preference can request a specific cap. Each operation reserves 512 MiB for the coordinator and writers and 512 MiB per worker within a 4 GiB scheduling budget. The reservation bounds concurrency; it is not a claim about process RSS. Existing decoder, row group, queue and writer limits still apply.

Consequences: the signed source group and canonical order stay independent of worker count. Disk preflight reserves scratch space for the largest concurrently staged sources. Windows EVTX retains serial helper launch with parallel hashing.

### One source pipeline for all presentations

Context: every compiled parser now has an original-field SourceDecoder and an
independently identified semantic or extraction-only mapping.

Decision: CLI, TUI, demo and object-storage acquisition use direct V3 preparation
and the same application-owned atomic signature assembly. Remove the opt-in
writer setting and its obsolete preference. Parser features include their
mapping implementation, while minimal builds can exclude individual parsers.

Consequences: an unmapped event remains valid and unclassified. No remote model
or connector is enabled. Existing current-format golden bytes, source checks,
rejection accounting, cancellation and atomic publication remain enforced.

The removed experimental-writer preference is no longer configurable. If it is
present in an authenticated configuration snapshot, startup requires explicit
configuration recovery. The snapshot hash and its original canonical bytes are
verified before offering restoration without the retired field; restoration
records a new signed approval and never rewrites the old operation.

### Keep canonical append and parallel partition completion

Context: the direct writer chooses file cuts from the live encoder state after
each append. Concurrent append would require a separate physical recipe.

Decision: keep append and eviction sequential in canonical order. Complete
independent partition writers concurrently after their file cuts are fixed.
Keep the existing constructor identity, physical goldens and reconstruction.

Consequences: there is no new append recipe or signed format. Worker-count
parity, bounded memory, cancellation, rollback and the absolute release gates
remain required. The native EVTX chunk trial did not justify enabling helper
parallelism; the distributed helper remains sequential on every platform.

### Retire per-source writer construction

Context: source decoding and identified mappings now cover every compiled parser.
The old local preparation API still exposed a second physical construction path.

Decision: remove per-source and legacy batch preparation, their writer factory
and obsolete projection/emission helpers. Keep only direct mapped preparation
for new artifacts. Keep the V2-shaped core used inside the current V3 envelope;
it is a component of that format, not an alternate ingestion route.

Consequences: the current direct writer keeps its physical recipe, sequential
canonical appends and parallel completion. Tests use actual decoder selection,
mapping profiles and bound V3 artifacts. Current direct physical golden bytes,
V6 wire goldens, offsets, spool authentication, cancellation and rollback remain
covered. Old-generation fixture generators are removed, along with their unused
base64 dependency. Removal of remaining historical schema readers is separate.

### Separate bounded-queue scheduling from writer cost in regression tests

Context: the exclusive-producer regression included 40,000 decoded and written
records within its scheduling deadline. That coupled a deadlock assertion to
unoptimized writer throughput and unrelated test load.

Decision: test the original exclusive-lease/full-queue cycle directly with the
production start permits and bounded channels. Keep the existing deadline and a
separate real-pipeline test for canonical decoder starts, current artifact bytes,
cancellation and complete rollback.

Consequences: the scheduling test still fails if a later producer can acquire
its lease before its canonical permit. It does not require a large Parquet write
to demonstrate a full queue. Production scheduling and limits are unchanged.
