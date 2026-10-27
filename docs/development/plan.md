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

| Milestone | Scope | Done when |
| --- | --- | --- |
| H0 Skeleton | Workspace, lints, CI, cargo-deny, dependency-direction test. | The test rejects an intentionally introduced reverse dependency. |
| H1 Domain | Typed IDs, risk and approval types, execution mode, actors, taint, scoped policy and quotas, case entities, pure hash-chain rules. | Tests cover every policy rule and chain failure. |
| H2 Application | Cancelable async remote ports; synchronous local ports through `spawn_blocking` in async use cases; investigation, approval, reporting, seal, verify, ingest, export, and export verification; generic module dispatch and port contracts. | No local operation blocks the runtime; each remote family has an approved-call end-to-end test; no raw data reaches the fake LLM. |
| H3 Security | Nonce isolation, normalization, injection detection, taint containment, safe output, startup corpus self-test, signed detection event. | An obedient fake LLM cannot execute an unapproved call; a broken rule blocks startup. |
| H4 Signed storage | SQLite WAL, SHA-256 evidence, distinct Analyst and Agent keys in an explicitly selected OS or encrypted-file backend, verify, seal, export, expected-key verification. | Verification detects database and evidence tampering. |
| H5 LLM | Streaming tool calls, case-state context, per-case token and cost limits. | Recorded-response tests and a documented manual test pass. |
| H6 TUI | Home case list and creation; chronological conversation with multiline input, scroll, command completion, optional case sidebar, and cards for calls and findings; cancelable work, first-run guide, module status, scope and evidence commands. | `ratatui::TestBackend` covers navigation, completion, cards, and a full case from creation through export without the CLI. |
| H7 Graph | DuckDB, hashed ingestion, streaming CloudTrail and JSON parsers, deterministic extraction, aggregated edges, text search, bounded Read tools. | A benchmark ingests at least 1 GB of synthetic data and measures time and tokens. |
| H8 Integrations | Cloud, SIEM, EDR, and threat-intelligence modules passing shared port contracts. | Each module has recorded-response tests and a setup guide. |

## Later unattended gateway

Do not implement the gateway yet. Preserve distinct Analyst and Agent signing keys, `ExecutionMode`, unattended scoped reads only, analyst-signed approvals, and service-safe concurrent use cases.

## Accepted design choices

- `ProposedCall` has no risk field. `Tool` determines risk.
- The evidence graph uses DuckDB.
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

The daily `main` CI run publishes unsigned binaries with `SHA256SUMS` when code changed in the preceding 24 hours. Signing, notarization, and Authenticode are deferred. Review this decision by 2027-04-24 or before external binary distribution.

## Documentation

English is authoritative. Public guides live under `docs/`; Spanish user guides identify the English source commit. Do not translate or alter signed event identifiers, canonical formats, or the bilingual attack corpus merely to localize documentation.
