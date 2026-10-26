# IRMind — Assisted Incident Response

[Spanish version](README.es.md)

A terminal AI client for security investigations with policy-enforced tool calls and a signed chain of custody.

> [!WARNING]
> IRMind is under development. Do not use it for real incidents or sensitive data yet.
> The examples in this repository are synthetic.

## What you can do

- Open a case, set its scope, and investigate an alert from one terminal workspace.
- Ingest local evidence and search a case timeline and entity graph.
- Ask a selected AI model to suggest investigative queries.
- Review and sign approvals before any external enrichment call.
- Inspect original evidence while the model receives a bounded, redacted copy.
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

The daily `main` CI run publishes unsigned binaries for Linux, macOS, and Windows when code changed in the preceding 24 hours. Verify `SHA256SUMS` before running one. Follow the [platform guide](docs/platforms.md) for checksums, keystore backends, SSH, and terminal support.

## First case in the TUI

1. Run `irmind` without a subcommand. Choose the OS keyring or encrypted-file backend for signing and module secrets. The file backend works over SSH without a graphical session. Save the analyst public-key fingerprint outside this computer.
2. Press `n` to create a case. Give it a title, severity, and a time window. Leave remote sources empty for a local-only case.
3. Open the case and enter `/ingest`. Select [examples/cloudtrail-alert.json](examples/cloudtrail-alert.json), which contains only synthetic data.
4. Choose a model explicitly. For a local OpenAI-compatible service such as Ollama, set `IRMIND_MODEL` to an installed model and `IRMIND_LLM_BASE_URL=http://127.0.0.1:11434/v1/`, then start `irmind --llm-module llm-openai-compatible`. HTTPS is also supported. For a remote provider, follow [configuration](docs/configuration.md) and obtain approval for its data handling first.
5. Reopen the case, describe the synthetic alert in the conversation panel, and inspect proposed calls. Use `/help` or `Ctrl+K` for case actions; `/pause` cancels a running task.
6. Review the timeline and evidence, then use `/verify`, `/report`, `/seal`, and `/export`. Sealing and export show the case hash and signing-key fingerprint before confirmation.

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
| JSON and CloudTrail parser | local parser | included | experimental | [Local parser](docs/modules.md#json-and-cloudtrail-parser) |
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
