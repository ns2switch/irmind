# Design decisions

This page is for maintainers reviewing tradeoffs that shape the current build. Each row states the context, choice, consequence, and decision date. The [reference plan](plan.md) holds acceptance criteria.

| Context | Decision | Consequence | Date |
| --- | --- | --- | --- |
| Model proposals cannot set their own privilege. | `Tool` determines risk; `ProposedCall` omits risk. | Policy owns authorization. | 2026-10-23 |
| Investigation sources include attacker-controlled text. | Mandatory guard, provenance, and fail-closed screening. | Original evidence stays local; detection is not perfect. | 2026-10-23 |
| Case evidence needs a reproducible local index. | Use DuckDB for the derived graph. | Signed originals, not the index, remain authoritative. | 2026-10-23 |
| Later unattended agents need distinct authority. | Analyst and Agent use separate Ed25519 keys and `ExecutionMode`. | Only analyst signatures resolve approvals. | 2026-10-23 |
| Product connectors must be replaceable. | Static Cargo modules implement application ports. | No runtime plugin loader; modules remain explicitly selected. | 2026-10-23 |
| Remote I/O and local custody have different costs. | Remote ports are async; local ports are synchronous and use `spawn_blocking` from async use cases. | Local work does not block the runtime. | 2026-10-25 |
| Native key storage may be unavailable over SSH. | Select `os` or encrypted `file` explicitly per signing and secret capability. | No silent fallback; an unavailable selected backend stops startup. | 2026-10-25 |
| The file keystore needs private writes without an adapter dependency. | Move ACL and durable-write helpers to `irmind-fs`. | Infra and keystore-file share one audited filesystem boundary; adapters cannot depend on adapters. | 2026-10-26 |
| Key migration can happen before the first case. | Record it once in a global signed operational chain. | Startup verifies the chain; historical case operations remain intact. | 2026-10-26 |
| Active connectors may retain a changed credential. | Warn in the TUI and offer `r` to rebuild the session. | The new value takes effect only after the composition root restarts. | 2026-10-26 |
| Local and remote TLS needs corporate roots. | Rustls uses native certificate roots; keyless local models may use loopback HTTP. | No system OpenSSL; platform-verifier checks are not fully replicated. | 2026-10-25 |
| A crash during sealing can leave two stores out of sync. | Sign the seal separately, persist seal intent first, and reconcile on startup. | Verification reports unresolved inconsistency. | 2026-10-25 |
| Sealed cases cannot accept more case-chain entries. | Record cancellations in a separate signed operational chain. | The case seal remains immutable. | 2026-10-25 |
| Analysts need one primary workflow. | `irmind` opens the TUI by default; CLI and TUI share application use cases. | Automation remains available through subcommands. | 2026-10-25 |
| Export and package verification must not depend on presentation. | Add local `CaseExporter` and `ExportVerifier` ports. | CLI and TUI use the same checks; package verification needs no keyring. | 2026-10-25 |
| Provider selection can expose evidence. | No LLM enabled by default; secrets are read by the composition root and injected. | Provider approval is a separate operating decision. | 2026-10-25 |
| Public distribution lacks a signing process. | Publish unsigned CI binaries with checksums. | Reassess signing by 2027-04-24 or before external distribution. | 2026-10-25 |
| Repeated release builds consume runner time without changing the binary. | Build unsigned binaries once daily on `main`, and only after code changes; PRs and merges still run tests. | Documentation-only changes run a lightweight check; CI test binaries are reused for cross-platform export verification. | 2026-10-26 |
| Analysts need settings that survive a TUI session without storing secrets. | Save versioned, non-secret module settings in a private `config.toml`; resolve flag, environment, file, then defaults. Check its hash against the last signed operational change. | Secrets stay in the selected keystore; unknown fields, secret fields, and unapproved file edits fail closed. | 2026-10-26 |
| Changing an active destination can expose case data. | Require attended analyst confirmation and a signed global operational event before enabling an LLM or connector or changing its active public settings. | The TUI composes a new session in the same process; temporary CLI and environment overrides remain read-only there. | 2026-10-26 |
| A crash can occur after the signed configuration event but before `config.toml` is replaced. | Store the complete canonical non-secret configuration in each new signed approval event; offer explicit restoration or reviewed acceptance before case work. | Older hash-only events still verify but cannot restore missing content. Automation fails closed until the TUI resolves a mismatch. | 2026-10-27 |
| Flags and environment settings may redirect a session without changing the saved file. | Show each effective egress override against its saved value before a TUI session; sign accepted overrides in the global chain. Automation signs effective overrides before running. | Rejection uses saved settings, and the status bar marks accepted overrides. | 2026-10-27 |
| Spanish translations cite their English source commit. | Check each citation against the last commit to change its source and warn on a stale translation. | A rebase merge can change commit IDs, so documentation PRs should use merge commits when citation hashes must remain exact. | 2026-10-26 |
| Public contributions need clear provenance. | Dual license MIT OR Apache-2.0 and require DCO on every PR commit. | CI checks author-matching sign-off. | 2026-10-25 |
| Free-form model SPL is difficult to constrain. | Proposed future structured SIEM query AST with allowed fields and escaped translation. | Not implemented; current Splunk accepts a bounded literal term. | 2026-10-25 |
| Incident reports must not promote unreviewed graph events into findings. | Keep graph events exploratory; report only analyst-confirmed timeline events and findings, each with evidence references. | Legacy signed finding payloads remain readable; new typed details add IOC, hypothesis, and technique fields. | 2026-10-27 |
| Case scope needs projects without breaking signed v1 strings. | Add v2 scope encoding and an optional policy TOML ceiling for sources, accounts, projects, hosts, and UTC window. | Existing v1 cases keep their behavior; out-of-ceiling calls become pending approvals. | 2026-10-27 |

The prompt-injection corpus intentionally contains English and Spanish attack samples. Its rule-set fingerprint can be recorded in signed audit data, so this documentation change does not rewrite those strings. Existing signed event identifiers and serialized formats also remain unchanged.
