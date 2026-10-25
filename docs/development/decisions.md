# Design decisions

This page is for maintainers reviewing tradeoffs that shape the current build. Each row states the context, choice, consequence, and decision date. The [reference plan](plan.md) holds acceptance criteria.

| Context | Decision | Consequence | Date |
| --- | --- | --- | --- |
| Model proposals cannot set their own privilege. | `Tool` determines risk; `ProposedCall` omits risk. | Policy owns authorization. | 2026-10-23 |
| Investigation sources include attacker-controlled text. | Mandatory guard, provenance, and fail-closed screening. | Original evidence stays local; detection is not perfect. | 2026-10-23 |
| Case evidence needs a reproducible local index. | Use DuckDB for the derived graph. | Signed originals, not the index, remain authoritative. | 2026-10-23 |
| Later unattended agents need distinct authority. | Analyst and Agent use separate Ed25519 keys and `ExecutionMode`. | Only analyst signatures resolve approvals. | 2026-10-23 |
| Product connectors must be replaceable. | Static Cargo modules implement application ports. | No runtime plugin loader; modules remain explicitly selected. | 2026-10-23 |
| Remote I/O and local custody have different costs. | Remote ports are async; local ports are synchronous and must run off the runtime when long. | Application use cases still need further `spawn_blocking` work. | 2026-10-25 |
| Native key storage may be unavailable. | Fail closed without a keyring; no encrypted-file fallback. | Key recovery is not yet available. | 2026-10-25 |
| Local and remote TLS needs corporate roots. | Rustls uses native certificate roots; keyless local models may use loopback HTTP. | No system OpenSSL; platform-verifier checks are not fully replicated. | 2026-10-25 |
| A crash during sealing can leave two stores out of sync. | Sign the seal separately, persist seal intent first, and reconcile on startup. | Verification reports unresolved inconsistency. | 2026-10-25 |
| Sealed cases cannot accept more case-chain entries. | Record cancellations in a separate signed operational chain. | The case seal remains immutable. | 2026-10-25 |
| Analysts need one primary workflow. | `irmind` opens the TUI by default; CLI and TUI share application use cases. | Automation remains available through subcommands. | 2026-10-25 |
| Export and package verification must not depend on presentation. | Add local `CaseExporter` and `ExportVerifier` ports. | CLI and TUI use the same checks; package verification needs no keyring. | 2026-10-25 |
| Provider selection can expose evidence. | No LLM enabled by default; secrets are read by the composition root and injected. | Provider approval is a separate operating decision. | 2026-10-25 |
| Public distribution lacks a signing process. | Publish unsigned CI binaries with checksums. | Reassess signing by 2027-04-24 or before external distribution. | 2026-10-25 |
| Public contributions need clear provenance. | Dual license MIT OR Apache-2.0 and require DCO on every PR commit. | CI checks author-matching sign-off. | 2026-10-25 |
| Free-form model SPL is difficult to constrain. | Proposed future structured SIEM query AST with allowed fields and escaped translation. | Not implemented; current Splunk accepts a bounded literal term. | 2026-10-25 |

The prompt-injection corpus intentionally contains English and Spanish attack samples. Its rule-set fingerprint can be recorded in signed audit data, so this documentation change does not rewrite those strings. Existing signed event identifiers and serialized formats also remain unchanged.
