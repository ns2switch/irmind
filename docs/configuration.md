# Configuration

This page is for operators setting up a controlled evaluation. It explains case scope, policy, non-secret settings, and keystore selection. For connector permissions, see [modules](modules.md).

## Case scope

A case can remain local-only. To permit remote reads, the TUI's new-case form asks for sources, accounts, hosts, and a UTC start and end time. `/scope` edits the same fields. Changes are signed. Queries outside the scope require approval or are denied. The automation encoding is documented in the [CLI reference](development/cli.md). Project IDs are not supported in the form yet.

## Policy file

Pass `--policy policy.toml` or set `IRMIND_POLICY`. The repository's [policy.toml](../policy.toml) is a versioned example:

```toml
version = 1
max_tool_calls_per_case = 100
max_model_result_bytes = 10000
max_model_tokens_per_case = 200000
denied_tools = []
```

Policy can tighten fixed tool rules, not enable denied actions. Read stays scoped; external enrichment needs a signed analyst approval; containment is disabled. Unknown fields fail validation.

## Non-secret settings

The TUI stores non-secret settings in `config.toml` in the [standard data directory](platforms.md#data-and-terminal-behavior). Press `m` to select the LLM and model, enable compiled connectors, and edit their public fields. Tab selects a field and `e` edits it. `k` opens its credentials in the keystore. The session reloads inside the TUI after a change. Activation or endpoint changes that may send data off this computer require explicit signed confirmation.

For automation, resolution order is **CLI flag > environment variable > config.toml > default**. An override lasts only for that run; the TUI does not silently replace it. The file contains module IDs, models, URLs, source IDs, indexes, regions, and optional pricing, but never credentials or passphrases. Unknown or secret manifest fields fail validation. Example:

```toml
version = 1
llm_module = "llm-openai-compatible"

[modules.llm-openai-compatible.values]
IRMIND_MODEL = "your-local-model"
IRMIND_LLM_BASE_URL = "http://127.0.0.1:11434/v1/"

[modules.siem-splunk]
enabled = false

[modules.siem-splunk.values]
IRMIND_SPLUNK_URL = "https://splunk.example.invalid/"
IRMIND_SPLUNK_SOURCE_ID = "demo"
IRMIND_SPLUNK_INDEX = "security"
```

This example describes the stored format. Change it through the TUI: a hand-edited file does not match the signed operational record and blocks startup. Restore the last approved file if an external edit was accidental.

These environment variables override their matching public fields. Set only values that match your approved endpoint and case scope.

| Variable | Purpose |
| --- | --- |
| `IRMIND_HOME` | Optional local data directory override. |
| `IRMIND_POLICY` | Path to a policy TOML file. |
| `IRMIND_LLM_MODULE` | Explicit model module selection; alternative to `--llm-module`. |
| `IRMIND_MODEL`, `IRMIND_LLM_BASE_URL` | OpenAI-compatible model and optional base URL. |
| `IRMIND_ANTHROPIC_MODEL`, `IRMIND_DEEPSEEK_MODEL`, `IRMIND_OPENROUTER_MODEL` | Provider model IDs. |
| `IRMIND_SPLUNK_URL`, `IRMIND_SPLUNK_SOURCE_ID`, `IRMIND_SPLUNK_INDEX`, `IRMIND_SPLUNK_ACCOUNT_FIELD` | Splunk endpoint and bounded search source. |
| `IRMIND_AWS_SOURCE_ID`, `IRMIND_AWS_REGION`, `IRMIND_AWS_ROLE_NAME` | AWS source, region, and required read-only role. |
| `IRMIND_CROWDSTRIKE_URL`, `IRMIND_CROWDSTRIKE_SOURCE_ID` | CrowdStrike endpoint and source. |
| `IRMIND_SENTINELONE_URL`, `IRMIND_SENTINELONE_SOURCE_ID`, `IRMIND_SENTINELONE_SITE_ID` | SentinelOne endpoint, source, and site. |
| `IRMIND_MISP_URL`, `IRMIND_MISP_SOURCE_ID` | MISP endpoint and internal source. |
| `IRMIND_INPUT_MICROUSD_PER_MILLION`, `IRMIND_OUTPUT_MICROUSD_PER_MILLION` | Optional model price estimate; set both together. |

VirusTotal has no non-secret module setting. Feature flags and enable switches are listed in [modules](modules.md).

## Signing and secret backends

The first-run TUI writes an explicit selection to `keystore.toml` in the local data directory:

```toml
[keystore]
signer = "file"
secrets = "file"
analyst_key_fingerprint = "<fingerprint shown by IRMind>"
```

Choose `os` or `file` independently for each capability. The OS backend uses Keychain, Credential Manager, or Secret Service. The encrypted-file backend keeps both capabilities in `keystore.enc`, prompts once per session without echo, and works over SSH. It uses Argon2id and XChaCha20-Poly1305; a strong passphrase and a protected host still matter. If a selected backend cannot be opened, IRMind fails closed and offers an explicit change in the TUI. It never falls back silently.

Press `k` on the home screen to view the active backends, check credential presence, add or replace a credential (`a`), delete one (`d`), change the file passphrase (`p`), or migrate a capability (`s` or `x`). Migration preserves the analyst public-key fingerprint and writes a signed global operational event even before the first case exists. After a credential change, active connectors may retain the previous value: press `r` to restart the session. Never type secrets into case text.

The CLI reads a file-backend passphrase from the terminal without echo or from an explicitly opened descriptor with `--passphrase-fd <FD>`; Windows currently accepts descriptor `0` only. IRMind does not accept passphrases or module secrets through arguments or environment variables. `verify-export` needs no keystore.

## Credential names

Do not set credential values in environment variables. Enter them in the TUI keystore view under the manifest field name below; IRMind never displays their values. With the OS backend, the service is `irmind-module` and the account is that field name. With the file backend, each field is an encrypted record.

| Account under `irmind-module` | Used by |
| --- | --- |
| `OPENAI_API_KEY` | Official OpenAI endpoint only. |
| `IRMIND_LLM_API_KEY` | Another OpenAI-compatible endpoint. |
| `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY` | Named LLM providers. |
| `IRMIND_SPLUNK_TOKEN` | Splunk read-only token. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | Dedicated AWS role credentials; session token when required. |
| `IRMIND_CROWDSTRIKE_CLIENT_ID`, `IRMIND_CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike API client. |
| `IRMIND_SENTINELONE_API_TOKEN` | SentinelOne site-scoped token. |
| `IRMIND_MISP_API_KEY` | MISP read-only key. |
| `VIRUSTOTAL_API_KEY` | VirusTotal enrichment key. |

The OS backend stores signing keys under a separate `irmind` service: `local-analyst` and `local-agent-<id>` for later unattended operation. The file backend stores the same identities encrypted. Both keep private keys inside the backend; a missing configured backend blocks signing.

## Choose a model

No provider is selected by default. In the TUI, press `m`, select the compiled OpenAI-compatible module, edit `IRMIND_MODEL` and `IRMIND_LLM_BASE_URL`, then press Enter to select it. Confirm the destination change. For an automated invocation, `--llm-module` and the matching environment variables override the saved selection and fields for that run.

A keyless local service may use HTTP only on loopback; HTTPS works there too. Remote endpoints require HTTPS and a destination-specific key. A different custom URL never inherits `OPENAI_API_KEY`. Select other compiled providers with their module IDs and settings in [modules](modules.md). Confirm retention, processing region, and data classification before any external connection.
