# IRMind reference plan

This internal plan is for maintainers tracking acceptance criteria. Public readers should use the [roadmap](roadmap.md). The English version is authoritative.

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

H7 is **done** as of 2026-10-29. The [standard-runner benchmark](https://github.com/ns2switch/irmind/actions/runs/40776509647) converted the synthetic 15 GB corpus in 216.761 seconds, kept measured query p95 below 10 seconds, and recorded the 1 GB profile. Migration, source verification, and graph verification have automated tests. This milestone covers local Parquet storage; cloud object reads remain H8 work.

## MVP

The MVP includes P: signed source manifests, optional original copies, partitioned Parquet, bounded direct queries over signed Parquet, the four streaming source parsers, representative 1 GB and 15 GB benchmarks, and verified migration of existing cases. It also includes R: read-only S3, GCS, and Azure Blob ingestion with explicit credentials, signed case scope v3 for bucket/container prefixes, transfer budgets, a prior signed listing, one streamed download to a private temporary spool, and a shared streaming contract. Existing v1/v2 scopes and signed audit, seal, and export layouts remain unchanged. C5 (SIEM alert retrieval and tracing), C6 (structured SIEM queries), and the existing H8 module contracts remain in scope. [Cloud query engines](cloud-query-design.md) are designed now but implemented after the MVP.

GCP and Azure enter the MVP only as object-storage read sources and exported-log parsers. Remote re-verification of cloud originals after a case is sealed, source-side queries, Chronicle, other GCP and Azure product connectors, external anchoring of case seals, and the local gateway with watches remain after the MVP. In the MVP, a signed repeat read rechecks a remote original while the case is open; a sealed case can verify an explicitly retained copy offline.

For uncopied originals, the signed manifest proves what IRMind observed when it hashed each source, while later full verification requires access to that same source. Sampling verifies only selected originals. Neither mode claims that an unavailable source remains intact. Export without originals is verifiable as a signed manifest and case chain, not as a complete portable evidence package.

Exit only when H0–H8 meet their stated acceptance criteria, the H5 manual test is documented, at least one connector has been tested against a real test environment, and a `v0.1.0` tag has a changelog and downloadable binaries. Synthetic recordings alone do not satisfy the connector test. Record the two manual results in [manual validation](manual-validation.md).

| MVP exit criterion | Status | Evidence or next action |
| --- | --- | --- |
| H0–H4 and H6 automated acceptance | Done | Workspace gates, signed custody, policy and TUI tests run in CI. |
| H7 local Parquet and benchmark acceptance | Done | [15 GB runner benchmark](https://github.com/ns2switch/irmind/actions/runs/40776509647) and migration tests. |
| H8 existing connector and object-source contracts | Done | Recorded synthetic contract suites and setup guides. |
| H5 recorded-response tests | Done | CI contract and application tests. |
| H5 conversation-loop correction | Pending agent | Integrate the reviewed Phase L work from PR #31 after the analyst's requested manual test. H5 as a whole remains open. |
| H5 manual test with real DeepSeek | Pending analyst | After Phase L is integrated, run the first procedure in [manual validation](manual-validation.md) and record the result. |
| One connector against a real test environment | Pending analyst | Run the Splunk lab procedure in [manual validation](manual-validation.md) and record the result. |
| Release dry run without a tag | Done | [Manual CI run 41117075395](https://github.com/ns2switch/irmind/actions/runs/41117075395) passed on Linux, macOS and Windows, including checksums and both Windows export cross-checks. No tag or GitHub Release was created. |
| `v0.1.0` tag, changelog and downloadable binaries | Pending agent | Tag only after manual results, approved work and green `main`; publish the reviewed changelog and CI artifacts. |

## Release process

The workspace version is `0.1.0`. Keep [CHANGELOG.md](../../CHANGELOG.md) as a draft until the MVP exit criteria above are met. Before the first tag, run the CI `release_dry_run` manual dispatch on a branch: it must build unsigned binaries and checksums for Linux, macOS and Windows and verify portable exports across platforms, without creating a tag or GitHub Release. Review the resulting artifacts and the green `main` checks. Only then create `v0.1.0` and publish its changelog and binaries. Do not treat a synthetic connector recording as the analyst's live test.

## Later unattended gateway

Do not implement the gateway yet. Preserve distinct Analyst and Agent signing keys, `ExecutionMode`, unattended scoped reads only, analyst-signed approvals, and service-safe concurrent use cases.

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

Release tags and nightly CI runs after code changes produce unsigned binaries with `SHA256SUMS`. Pull requests and merges to `main` run development checks without release builds. Signing, notarization, and Authenticode are deferred. Review this decision by 2027-04-24 or before external binary distribution.

## Documentation

English is authoritative. Public guides live under `docs/`; Spanish user guides identify the English source commit. Do not translate or alter signed event identifiers, canonical formats, or the bilingual attack corpus merely to localize documentation.
