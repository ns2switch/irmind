# Architecture

This page is for contributors changing application behavior or adding a connector. It identifies dependency boundaries, shows one tool-call path, and gives a module checklist. Operators should start with [modules](../modules.md).

## Layers

```text
domain ← application ← adapters / security / TUI ← binary

shared filesystem and protocol crates support adapters without depending on them
```

| Layer | Crates | Responsibility |
| --- | --- | --- |
| Domain | `irmind-domain` | Cases, typed IDs, taint, risk, policy, approval challenges, pure custody rules. Depends on `std` and `sha2` for pure hashing. |
| Application | `irmind-app` | Use cases, remote and local ports, registry, dispatch, report, and audit orchestration. |
| Adapters | `irmind-mod-*`, `irmind-infra` | Product APIs, SQLite, DuckDB, evidence files, and signing backends. |
| Shared support | `irmind-fs`, `irmind-keystore-transfer`, `irmind-llm-chat-completions` | Private file operations, encrypted key transfer, and common model protocol handling. No dependency on a product adapter. |
| Mandatory security | `irmind-security` | Normalization, detection, redaction, and output screening. |
| Presentation | `irmind-tui` | Analyst screens and commands; it calls application use cases. |
| Composition | `irmind` | Selects signing and secret backends, injects credentials, registers compiled modules, starts TUI or CLI automation. |

`irmind-testkit` contains fake ports and shared contracts. The workspace test built with `cargo_metadata` rejects reverse edges and production dependencies between adapters. Most crates forbid unsafe Rust; the reviewed Win32 ACL boundary in `irmind-fs` is the only explicit exception.

Remote ports are async and accept a `CancellationToken`. Local ports stay synchronous; a long local operation runs off the UI thread and checks cancellation between batches. Case locks and SQLite WAL coordinate concurrent activity for one case.

## One model-proposed call

```text
LLM response
  → ProposedCall
  → schema and policy evaluation
  → Allow / Deny / NeedsApproval
  → signed analyst approval when required
  → AuthorizedCall
  → registry dispatch to a remote port
  → original bytes stored by hash
  → guarded and redacted copy for the model
  → signed audit entries throughout
```

`AuthorizedCall` has private fields. Only domain policy evaluation or signed approval resolution can create it. The module receives that type and cannot bypass the application dispatch by accepting a raw model proposal. Tool risk comes from the `Tool` enum; the model cannot choose it. External values carry typed provenance until an analyst signs a release.

The audit log and case state share a SQLite transaction. Case sealing signs a prepared final hash and evidence manifest. A separate case operational chain records cancellations after sealing. A global operational chain records keystore migrations, including before any case exists. The DuckDB graph is derived from signed evidence and can be rebuilt.

## Add a product module

1. Add a crate under `crates/modules/` with the workspace toolchain, license, lint settings, and `#![forbid(unsafe_code)]`.
2. Select the appropriate port: `LlmPort`, `SiemPort`, `EdrPort`, `CloudAuditPort`, `InternalIntelPort`, or `ThreatIntelPort`. Do not change the domain for a new product.
3. Declare a stable module ID and `ModuleManifest`. List only capabilities actually implemented. Mark each configuration field as secret or non-secret.
4. Implement `Module::register`. The binary reads non-secret settings and credentials from the selected secret backend, validates `ModuleConfig`, and injects them. The product module must not read the environment or keystore.
5. Accept only `AuthorizedCall` for external tool execution. Validate the tool, source, target, time window, response scope, timeout, and size. Require HTTPS for remote endpoints and disable redirects. A local model may use keyless loopback HTTP.
6. Return original evidence bytes to the application. Do not redact, audit, or make policy decisions inside the adapter; the application owns those steps.
7. Add recorded synthetic responses and run the relevant `irmind-testkit` contract. Add a Cargo feature and explicit selection in the binary, then document required privileges and limits in [modules](../modules.md).

For Chat Completions providers, reuse `irmind-llm-chat-completions`. Anthropic uses a separate native Messages adapter. New modules remain frozen until the current structural and documentation work is reviewed.
