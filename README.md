[Spanish version](README.es.md)

# IRMind — Assisted Incident Response

A terminal AI client for security investigations with policy-enforced tool calls and a signed chain of custody.

IRMind is an agentic terminal assistant for incident response and digital forensics: the analyst converses with an agent that investigates local and remote evidence, loads forensic skills when needed, and delegates bounded work to parallel subagents. The model proposes, policy decides, and every action is signed.

![Synthetic IRMind TUI walkthrough showing a resumed case, slash commands, local evidence ingestion, streaming model text, and a numbered approval](docs/assets/demo.gif)

*The demo uses synthetic evidence and an ephemeral key. Its scripted model needs no network or account.*

> [!WARNING]
> IRMind 0.1.1 is a preliminary release for evaluation with synthetic data. It has not passed manual validation with a real model or connector. Do not use it for real incidents or sensitive data.

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

The [v0.1.1 pre-release](https://github.com/ns2switch/irmind/releases/tag/v0.1.1) provides keyless Sigstore bundles, GitHub provenance, an SBOM, and checksums. Download a binary and `SHA256SUMS`, verify their exact signer identity and checksums with cosign 3.1.3 or newer, then check `gh attestation verify`. The [platform guide](docs/platforms.md#verify-a-release-before-installing) has the commands. After verifying a downloaded copy of [install.sh](install.sh) or [install.ps1](install.ps1), the installer can perform these checks for you.

```sh
# After downloading the binary, SHA256SUMS, and both .sigstore.json bundles:
tag=v0.1.1; binary=irmind-linux-x86_64
for file in "$binary" SHA256SUMS; do
  cosign verify-blob "$file" --bundle "$file.sigstore.json" --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/$tag" --certificate-oidc-issuer https://token.actions.githubusercontent.com
done
awk -v name="$binary" '$2 == name { print }' SHA256SUMS | sha256sum -c -
gh attestation verify "$binary" -R ns2switch/irmind
```

## Try it in five minutes

Run `irmind demo` from a verified build, or type `/demo` on the home screen. IRMind opens a temporary, signed case with a bundled synthetic HuntEval episode. It creates a random encrypted file keystore without asking for a passphrase and deletes the whole demo when you exit. If a local Ollama model advertises tool support, you may select it with the arrow keys; otherwise the clearly labeled scripted model runs offline. No remote model is used.

Ask “What happened in this synthetic episode?” to see a local graph lookup, a proposed finding, and an external enrichment proposal that still needs signed approval. The external result is simulated and makes no network call. Confirm a finding, then type `/demo check` to compare it locally with the bundled answers. The answers never enter the model context. On exit, use `/new` and `/settings` to start a real case.

## First case in the TUI

1. Run `irmind`. The first-run guide sets up signing and secrets backends; enter and confirm a masked passphrase if you choose the file backend. Save the analyst key fingerprint outside this computer. Choose a model in the guide or type `/settings model` afterward. No model is selected by default.
2. Type `/new`, enter a title, and choose a severity with the arrow keys. Enter creates a local case; the second form step adds optional remote scope.
3. In the case, type `/ingest` and select the synthetic [CloudTrail example](examples/cloudtrail-alert.json). IRMind hashes the file in place; copying the original is an explicit option.
4. Ask what the synthetic role assumption suggests, then press Enter. The response streams into the conversation. You can also chat without starting an investigation.
5. Review the proposed tool call. An external lookup waits for a signed approval; choose a numbered option with the arrows and Enter. Type `/` for commands, `Ctrl+K` for the palette, `/pause` to cancel active work, or `/continue` after a model limit.
6. Use `/verify <source-root>` to check the original, then review `/report` before `/seal` and `/export`. The latter two show the case hash and signing-key fingerprint before confirmation.

You can ingest, inspect, and verify local evidence without a model. On later starts, IRMind verifies and reopens your most recently used open case. Use `/home` for the case list or `/settings preferences` to disable this behavior. `/settings` also manages connectors, credentials, mouse capture, and theme. `/help` lists the slash commands and reserved keys: Enter, Esc, arrows, Tab/Shift+Tab, PgUp/PgDn, Ctrl+C, Ctrl+K, and Ctrl+O. Printable characters, including `/`, go into the focused form field; bracketed paste works there too.

## Modules

The normal build includes every current product module and both keystores. None is enabled until selected and configured. A smaller build uses `--no-default-features --features keystore-file` (at least one signer and secrets backend is required). All modules are experimental.

`/settings model` also has local LM Studio and vLLM presets and remote Mistral, Groq, Google Gemini, xAI, and Together presets. They reuse the OpenAI-compatible module; see [provider URLs and limits](docs/modules.md#openai-compatible).

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

## Roadmap

- **v0.1.x:** Stabilize the pre-release, validate a model and connector, and add verifiable release assets.
- **v0.2:** Add modular log parsers and structured-query SIEM connectors.
- **v0.3:** Add signed, progressively loaded forensic skills.
- **v0.4:** Add bounded parallel subagents and streamed engine events.
- **Public launch:** Publish the demo, benchmark, and initial community skills catalog.
- **v0.5:** Add budgeted source-side cloud queries.
- **v0.6:** Add local detections, exportable reports, controlled extensions, and a headless engine API.
- **1.0:** Stabilize signed formats and complete external security and connector validation.

See the [public roadmap](docs/development/roadmap.md) for scope and limits; these are intentions, not release commitments.

## Documentation

- [Getting started](docs/getting-started.md) · [Configuration](docs/configuration.md) · [Modules](docs/modules.md)
- [Platforms](docs/platforms.md) · [Security model](docs/security-model.md)
- [Architecture and development](docs/development/architecture.md) · [CLI automation](docs/development/cli.md) · [Roadmap](docs/development/roadmap.md)

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the DCO and synthetic-data rules, and follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Do not include real incident data in issues or pull requests.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT)),

at your option. Unless you explicitly state otherwise, a contribution intentionally submitted for inclusion is dual licensed under the same terms, without additional conditions.
