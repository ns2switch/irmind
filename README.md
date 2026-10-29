[Spanish version](README.es.md)

# IRMind — Assisted Incident Response

A terminal AI client for security investigations with policy-enforced tool calls and a signed chain of custody.

![IRMind synthetic walkthrough: a case, evidence, a model proposal, signed approval, and verification](docs/assets/demo.gif)

*This offline demo uses synthetic evidence, an ephemeral file keystore, and a fake model.*

> [!WARNING]
> IRMind is under development. Do not use it for real incidents or sensitive data yet.
> The examples in this repository are synthetic.

## What you can do

- Open a case, set its scope, and investigate an alert from one terminal workspace.
- Ingest local evidence and search a case timeline and entity graph.
- Ask a selected AI model to suggest investigative queries.
- Review and sign approvals before any external enrichment call.
- Inspect indexed records and available originals while the model receives bounded, redacted data.
- Verify, seal, export, and independently verify a case package.

## How it works

The model suggests a tool call. The policy checks its tool, arguments, case scope, execution mode, and limits. Approved connectors return evidence that stays local; the model sees a guarded copy. The signed audit trail records the proposal, decision, result, and case changes.

```text
Analyst → TUI → case + policy → authorized connector → local evidence
                  ↑       ↓
                 model   signed audit chain
```

See the [security model](docs/security-model.md) for the guarantees and their limits.

## Install

Build from source for internal evaluation:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
./target/release/irmind
```

No released binaries are available yet. CI produces unsigned artifacts only on release tags and on nightly runs after code changes. Verify `SHA256SUMS` before running one. Follow the [platform guide](docs/platforms.md) for checksums, keystore backends, SSH, and terminal support.

## First case in the TUI

1. Run `irmind` without a subcommand. The first-run wizard explains signing, recommends the encrypted-file backend when no system keyring is available, and asks for a passphrase twice in masked TUI fields. It works over SSH. Save the analyst public-key fingerprint outside this computer.
2. Press `n` to create a case. Give it a title, severity, and a time window. Leave remote sources empty for a local-only case.
3. Open the case and enter `/ingest`. Select [examples/cloudtrail-alert.json](examples/cloudtrail-alert.json), which contains only synthetic data. IRMind hashes the file in place; copying the original is an explicit option.
4. Return to the home screen and press `m`. Select the OpenAI-compatible module, press `e` to set an installed model and a local base URL such as `http://127.0.0.1:11434/v1/`, then confirm the change. The session reloads inside the TUI. For a remote provider, follow [configuration](docs/configuration.md) and approve its data handling first.
5. Open the case again and describe the synthetic alert in the conversation. Enter sends; Alt+Enter adds a line. Scroll with PgUp/PgDn, use `Ctrl+B` for the case sidebar, and type `/` for grouped command suggestions. `Ctrl+K` opens the command palette; `Ctrl+O` expands a selected result. On a selected approval, use the arrow keys and Enter or 1/2/3. `/pause` or Esc cancels a running task.
6. Review the timeline and indexed records, then use `/verify <source-root>`, `/report`, `/seal`, and `/export`. Sealing and export show the case hash and signing-key fingerprint before confirmation.

No LLM is enabled by default. You can ingest, inspect, and verify local evidence without one.

## Modules

A Cargo feature includes a module in the binary; enabling a connector or selecting a model is a separate step. All modules are experimental while IRMind is under development.

| Module | Type | Cargo feature | Status | Setup |
| --- | --- | --- | --- | --- |
| OpenAI-compatible, including local Ollama | LLM | included | experimental | [LLM setup](docs/modules.md#openai-compatible) |
| Anthropic | LLM | `llm-anthropic` | experimental | [LLM setup](docs/modules.md#anthropic) |
| DeepSeek | LLM | `llm-deepseek` | experimental | [LLM setup](docs/modules.md#deepseek) |
| OpenRouter | LLM | `llm-openrouter` | experimental | [LLM setup](docs/modules.md#openrouter) |
| Splunk | SIEM | `siem-splunk` | experimental | [Splunk](docs/modules.md#splunk) |
| AWS CloudTrail and IAM | cloud | `cloud-aws` | experimental | [AWS](docs/modules.md#aws-cloudtrail-and-iam) |
| CrowdStrike | EDR | `edr-crowdstrike` | experimental | [CrowdStrike](docs/modules.md#crowdstrike) |
| SentinelOne | EDR | `edr-sentinelone` | experimental | [SentinelOne](docs/modules.md#sentinelone) |
| MISP | internal threat intel | `ti-misp` | experimental | [MISP](docs/modules.md#misp) |
| VirusTotal | external enrichment | `ti-virustotal` | experimental | [VirusTotal](docs/modules.md#virustotal) |
| JSON and exported cloud log parser | local parser | included | experimental | [Local parser](docs/modules.md#streaming-json-and-exported-cloud-log-parser) |
| OS keystore | signing and secrets | `keystore-os` (default) | experimental | [OS keystore](docs/modules.md#os-keystore) |
| Encrypted-file keystore | signing and secrets | `keystore-file` (default) | experimental | [File keystore](docs/modules.md#file-keystore) |

## Security model

- External tools accept only authorized calls. Unattended work permits only scoped reads.
- External enrichment waits for a signed analyst approval; containment is disabled.
- Original evidence stays local, while model input is bounded, guarded, and redacted.
- Audit entries are hash chained and signed; a sealed export can be checked on another computer. Keystore migrations enter a separate signed global chain.
- Pattern-based redaction can miss data, and a local signer can rewrite an entire chain unless its key fingerprint is pinned elsewhere. Do not treat this build as production-ready.

Read [security-model.md](docs/security-model.md) before connecting a provider.

## Documentation

- [Getting started](docs/getting-started.md) · [Configuration](docs/configuration.md) · [Modules](docs/modules.md)
- [Platforms](docs/platforms.md) · [Security model](docs/security-model.md)
- [Architecture and development](docs/development/architecture.md) · [CLI automation](docs/development/cli.md) · [Roadmap](docs/development/roadmap.md)

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the DCO and synthetic-data rules. Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Do not include real incident data in issues or pull requests.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT)),

at your option. Unless you explicitly state otherwise, a contribution intentionally submitted for inclusion is dual licensed under the same terms, without additional conditions.
