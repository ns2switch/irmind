# IRMind reference plan

This internal plan records historical acceptance criteria and decisions behind the first pre-releases. Future sequence and ownership follow the [public roadmap](roadmap.md); this document does not set future release dates or assign the unattended gateway to this repository. The English version is authoritative.

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

The 0.1.0 scope included GCP and Azure only as object-storage read sources and exported-log parsers. The new roadmap places Chronicle with the v0.2 connectors, source-side queries and remote re-verification in v0.5, and the unattended gateway and watches in another repository after the engine API. A signed repeat read rechecks a remote original while a case is open; a sealed case can verify an explicitly retained copy offline.

For uncopied originals, the signed manifest proves what IRMind observed when it hashed each source, while later full verification requires access to that same source. Sampling verifies only selected originals. Neither mode claims that an unavailable source remains intact. Export without originals is verifiable as a signed manifest and case chain, not as a complete portable evidence package.

The original MVP exit criteria remain: H0–H8 meet their stated acceptance criteria, the H5 manual test is documented, at least one connector has been tested against a real test environment, and the release has a changelog and downloadable binaries. Synthetic recordings alone do not satisfy the connector test. The analyst approved an explicit exception for `v0.1.0`: publish it as a pre-release before the two manual validations. H5 has since been closed by analyst decision after a real DeepSeek greeting test, as recorded in [manual validation](manual-validation.md#result-record). The live-connector gate remains open. Unreported H5 procedure steps remain pending analyst records; the tag itself does not satisfy any validation gate.

| MVP exit criterion | Status | Evidence or next action |
| --- | --- | --- |
| H0–H4 and H6 automated acceptance | Done | Workspace gates, signed custody, policy and TUI tests run in CI. |
| H7 local Parquet and benchmark acceptance | Done | [15 GB runner benchmark](https://github.com/ns2switch/irmind/actions/runs/40776509647) and migration tests. |
| H8 existing connector and object-source contracts | Done | Recorded synthetic contract suites and setup guides. |
| H5 recorded-response tests | Done | CI contract and application tests. |
| H5 conversation-loop correction | Done | PR #31 integrated with the trusted-system-role security correction; no manual DeepSeek test was run before merge. The later analyst acceptance is recorded below. |
| H5 manual test with real DeepSeek | Done by analyst decision | The analyst observed a natural reply to `hola` without unnecessary tool calls. See the [result record](manual-validation.md#result-record); the analyst supplied model `deepseek v4.1 flash`, test date 2026-11-01, IRMind 0.1.2 and Debian Linux 12. An exact commit and unreported procedure steps remain pending records. |
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
- Parquet is the derived local event store for large cases; Arrow reads only signed IRMind-produced artifacts. Original copies are an explicit option rather than an implicit requirement. The analyst approved the versioned source and artifact records and streaming v4 export; the existing signed entry encoding and v3 export remain valid.
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

The experimental `parser-declarative` module is integrated through [PR #151](https://github.com/ns2switch/irmind/pull/151) behind a default Cargo feature. Definitions are strict, bounded TOML, compiled only from approved bytes, with low-confidence detection requiring analyst selection. New additive parser identity methods borrow dynamic names/versions; catalog keys own their strings. Native parser methods keep their defaults. Signed `SourceManifestV2` and `ParquetArtifactV1` tags and encodings remain unchanged: the existing parser-version field contains the definition SHA-256. Install/change/deactivate/restore use the current signed global operational envelope and private atomic storage. Historical resolution uses verified signed snapshots. The analyst approved the additive port changes before merge; the artifact-v2 design in #143 has separate analyst approval; its implementation follows JSON-order independence and syslog/Linux.

## Approved timestamp precision design

[Parquet artifact V2](parquet-artifact-v2-design.md) addresses [issue #143](https://github.com/ns2switch/irmind/issues/143): precise UTC instants, stable equal-time ordering, compatible reads and explicit verified migration. The analyst approved the revised design and implementation with generic, bounded scope partitions and signed overflow. Start host cardinality at 64; the 15 GB benchmark selects the default, with an immutable ceiling of 1,024. Implement only after JSON-order independence and syslog/Linux are complete, in separate PRs for types/envelope and golden bytes, mixed V1/V2 writes/reads, partitions, migration, export v5 and benchmarks. Stop before the first merge if implementation needs a design change. Existing parsers must retain full source timestamps while the current derived index remains second precision.

## Approved parser and precision work order

1. Make signed, hashed and reconstructed output independent of `serde_json::Map` order; test unchanged golden bytes with `preserve_order` enabled. A changed existing golden requires analyst review.
2. Deliver separate syslog and Linux modules, retaining explicit/inferred timestamp context. The analyst approved reviewed `flate2` for bounded gzip; Linux adds no new dependencies.
3. Implement the approved artifact-v2 design in the separate PRs listed above.
4. Add EVTX through an isolated `irmind-evtx` helper in its own Cargo workspace, using official upstream `evtx` without a fork. Its features must not unify with the main workspace. The helper has no network or shell, fixed arguments, bounded runtime/output and untrusted NDJSON with source provenance. Rejection is atomic; unavailable helpers remain visible as unavailable. Include signed release/install assets, attestations, SBOM and an unsafe report. Run malformed-input fuzzing for at least one hour and nightly. Ask before merge because it adds dependencies and a distributed binary.

## Native syslog parser

The experimental feature-gated `parser-syslog` uses the shared detection registry and existing SourceManifestV2. RFC 5424 retains source precision; RFC 3164 binds explicit year and fixed offset into the signed inference context and parser version. Bounded gzip uses the reviewed, analyst-approved `flate2` dependency. Synthetic contracts, signed ingestion/reconstruction, unchanged-format goldens, fuzzing and local throughput measurements are documented in [the parser contract](syslog-parser.md) and [benchmarks](benchmarks.md). Linux remains the next module; artifact-V2 implementation has not started.
