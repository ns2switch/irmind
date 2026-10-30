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

1. Run `irmind` without a subcommand. Choose signing and secrets backends with the arrow keys and Enter, then enter and confirm the masked passphrase if using a file keystore. It works over SSH. Save the analyst key fingerprint outside this computer. The optional “AI model” step can be skipped.
2. On the home screen, type to filter case titles or use `/cases open|sealed|inconsistent` for status. Type `/new`, enter a title, and choose a severity; Enter creates a local case. The second step adds optional remote scope and a UTC window.
3. Open the case and enter `/ingest`. Select [examples/cloudtrail-alert.json](examples/cloudtrail-alert.json), which contains only synthetic data. IRMind hashes the file in place; copying the original is an explicit option.
4. Type `/model` to choose Ollama, an OpenAI-compatible endpoint, Anthropic, DeepSeek, or OpenRouter. Ollama lists installed models from `http://127.0.0.1:11434`; remote keys go into the selected secrets backend. Use “Test connection” with synthetic text and explicitly confirm remote data transfer. The session reloads inside the TUI.
5. Open the case again and describe the synthetic alert. Enter sends. Type `/` for commands, `Ctrl+K` for the palette, `/sidebar` for case panels, and `Ctrl+O` to expand a selected card. PgUp/PgDn scroll. On an approval, select an option with the arrows and Enter, or type its number followed by Enter. `/pause` or Esc cancels a running task.
6. Review the timeline and indexed records, then use `/verify <source-root>`, `/report`, `/seal`, and `/export`. Sealing and export show the case hash and signing-key fingerprint before confirmation.

No LLM is enabled by default. You can ingest, inspect, and verify local evidence without one.
On later starts, IRMind verifies and reopens your most recently used open case. Use `/home` for the case list or `/config` to disable this behavior.

## Modules

The normal build includes every current product module and both keystores. None is enabled until selected and configured. A smaller build uses `--no-default-features --features keystore-file` (at least one signer and secrets backend is required). All modules are experimental.

| Module | Type | Cargo feature | Status | Setup |
| --- | --- | --- | --- | --- |
| OpenAI-compatible, including local Ollama | LLM | included | experimental | [LLM setup](docs/modules.md#openai-compatible) |
| Anthropic | LLM | `llm-anthropic` | experimental | [LLM setup](docs/modules.md#anthropic) |
| DeepSeek | LLM | `llm-deepseek` | experimental | [LLM setup](docs/modules.md#deepseek) |
| OpenRouter | LLM | `llm-openrouter` | experimental | [LLM setup](docs/modules.md#openrouter) |
| Splunk | SIEM | `siem-splunk` | experimental | [Splunk](docs/modules.md#splunk) |
| AWS CloudTrail and IAM | cloud | `cloud-aws` | experimental | [AWS](docs/modules.md#aws-cloudtrail-and-iam) |
| S3 object storage | cloud storage | `storage-s3` | experimental | [Object storage](docs/modules.md#cloud-object-storage-s3-gcs-azure-blob) |
| GCS object storage | cloud storage | `storage-gcs` | experimental | [Object storage](docs/modules.md#cloud-object-storage-s3-gcs-azure-blob) |
| Azure Blob object storage | cloud storage | `storage-azure` | experimental | [Object storage](docs/modules.md#cloud-object-storage-s3-gcs-azure-blob) |
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
