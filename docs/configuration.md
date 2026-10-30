# Configuration

This page is for operators setting up a controlled evaluation. It explains case scope, policy, non-secret settings, and keystore selection. For connector permissions, see [modules](modules.md).

## Case scope

A case can remain local-only. To permit remote reads, the TUI's new-case form asks for sources, accounts, projects, hosts, object prefixes, and a UTC start and end time. An object prefix looks like `s3://audit-bucket/AWSLogs/123/CloudTrail/`, `gs://bucket/export/`, or `az://container/export/`. Add one with `/scope add object <URI>`; the source ID must also be in the case scope. Other targets use `/scope add project <id>` (or `source`, `account`, `host`). Widen the window with `/scope window <from> <to>`. Changes are signed by the analyst. Object reads outside the case or organization prefix are denied. The automation encoding is documented in the [CLI reference](development/cli.md).

## Policy file

Pass `--policy policy.toml` or set `IRMIND_POLICY`. The repository's [policy.toml](../policy.toml) is a versioned example:

```toml
version = 1
max_tool_calls_per_case = 100
max_model_result_bytes = 10000
max_model_tokens_per_case = 200000
max_object_read_bytes = 1073741824
max_object_bytes_per_case = 536870912000
object_transfer_approval_bytes = 67108864
denied_tools = []

[scope]
sources = ["demo"]
accounts = ["123456789012"]
projects = []
hosts = []
objects = ["s3://audit-bucket/AWSLogs/123/CloudTrail/"]
from = "2026-10-23T00:00:00Z"
to = "2026-10-23T23:59:59Z"
```

The optional `[scope]` table is a hard ceiling for remote reads across cases. It can list accounts, projects, hosts, and object prefixes together, plus allowed sources and a UTC window. An object read outside either the case prefix or policy ceiling is denied, even with approval. Other remote reads outside the case scope may need analyst approval; a read outside the policy ceiling is denied. New cases and scope changes cannot exceed the ceiling. If a new policy narrows an existing case, its reads use the intersection and the TUI shows a warning. The current AWS connector requires an account; project queries remain unavailable until a connector supports them. Policy can tighten fixed tool rules, not enable denied actions. External enrichment needs a signed analyst approval; containment is disabled. Unknown fields fail validation.

## Non-secret settings

The TUI stores non-secret settings in `config.toml` in the [standard data directory](platforms.md#data-and-terminal-behavior). The normal build compiles all current product modules and both keystores but enables none. Type `/model` to choose a provider and model; type `/modules` to enable connectors and inspect their public fields. Tab selects a field, `/edit-param` edits it, and `/keystore` opens credentials. The session reloads inside the TUI after a change. Activation or endpoint changes that may send data off this computer require explicit signed confirmation. A minimal build uses `--no-default-features --features keystore-file` because a signer and secrets backend must remain available.

`resume_last_case` defaults to `true`. After startup, the TUI reopens the most recently used open case only if its custody chain verifies. Sealed or deleted cases stay on the home screen; a verification failure appears there as a warning. Use `/config` to turn resumption off or on. The private `last-case` reference is stored beside `config.toml` and is not part of custody. CLI automation does not resume a case.

For automation, resolution order is **CLI flag > environment variable > config.toml > default**. An override lasts only for that run; the TUI does not silently replace it. The file contains module IDs, models, URLs, source IDs, indexes, regions, and optional pricing, but never credentials or passphrases. Unknown or secret manifest fields fail validation. Example:

```toml
version = 1
llm_module = "llm-openai-compatible"
mouse_capture = false # optional: leave terminal text selection available
resume_last_case = true # optional: reopen the last verified open case

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

This example describes the stored format. Change it through the TUI. If the file is missing or differs from the last signed version, startup pauses before opening cases. The TUI can restore the approved version or show changed fields and sign the current valid file. It never accepts or restores silently. A secret field is always rejected. Automation exits with instructions to resolve the mismatch in the TUI.

When a flag or environment variable changes a model, endpoint, connector selection, source ID, index, or region, the TUI first shows its effective and saved values. Accepting signs the overrides for that session and keeps an override indicator visible. Rejecting uses the saved settings. CLI automation accepts effective overrides without a prompt and records them in the signed global chain before running.

These environment variables override their matching public fields. Set only values that match your approved endpoint and case scope.

| Variable | Purpose |
| --- | --- |
| `IRMIND_HOME` | Optional local data directory override. |
| `IRMIND_POLICY` | Path to a policy TOML file. |
| `IRMIND_LLM_MODULE` | Explicit model module selection; alternative to `--llm-module`. |
| `IRMIND_ENABLE_SPLUNK`, `IRMIND_ENABLE_AWS`, `IRMIND_ENABLE_CROWDSTRIKE`, `IRMIND_ENABLE_SENTINELONE`, `IRMIND_ENABLE_MISP`, `IRMIND_ENABLE_VIRUSTOTAL` | Temporary connector enable overrides (`true` or `false`). |
| `IRMIND_ENABLE_STORAGE_S3`, `IRMIND_ENABLE_STORAGE_GCS`, `IRMIND_ENABLE_STORAGE_AZURE` | Temporary object-storage enable overrides (`true` or `false`). |
| `IRMIND_MODEL`, `IRMIND_LLM_BASE_URL` | OpenAI-compatible model and optional base URL. |
| `IRMIND_ANTHROPIC_MODEL`, `IRMIND_DEEPSEEK_MODEL`, `IRMIND_OPENROUTER_MODEL` | Provider model IDs. |
| `IRMIND_SPLUNK_URL`, `IRMIND_SPLUNK_SOURCE_ID`, `IRMIND_SPLUNK_INDEX`, `IRMIND_SPLUNK_ACCOUNT_FIELD`, `IRMIND_SPLUNK_ALERT_ID_FIELD` | Splunk endpoint, bounded index, and optional alert ID field (default `alert_id`). |
| `IRMIND_SPLUNK_EVENT_NAME_FIELD`, `IRMIND_SPLUNK_USER_FIELD`, `IRMIND_SPLUNK_SOURCE_IP_FIELD`, `IRMIND_SPLUNK_HOST_FIELD` | Optional Splunk index field names for the four structured search fields; defaults are `eventName`, `user`, `sourceIPAddress`, and `host`. |
| `IRMIND_AWS_SOURCE_ID`, `IRMIND_AWS_REGION`, `IRMIND_AWS_ROLE_NAME` | AWS source, region, and required read-only role. |
| `IRMIND_STORAGE_S3_SOURCE_ID`, `IRMIND_STORAGE_S3_BUCKET`, `IRMIND_STORAGE_S3_REGION`, `IRMIND_STORAGE_S3_ENDPOINT` | S3 source, bucket, region, and optional HTTPS endpoint. |
| `IRMIND_STORAGE_GCS_SOURCE_ID`, `IRMIND_STORAGE_GCS_BUCKET`, `IRMIND_STORAGE_GCS_ENDPOINT` | GCS source, bucket, and optional HTTPS endpoint. |
| `IRMIND_STORAGE_AZURE_SOURCE_ID`, `IRMIND_STORAGE_AZURE_ACCOUNT`, `IRMIND_STORAGE_AZURE_CONTAINER`, `IRMIND_STORAGE_AZURE_CLIENT_ID`, `IRMIND_STORAGE_AZURE_TENANT_ID`, `IRMIND_STORAGE_AZURE_ENDPOINT` | Azure Blob source, account, container, service principal identity, and optional HTTPS endpoint. |
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

Type `/keystore` to view active backends and credential presence. Use `/cred-add`, `/cred-delete`, `/passphrase`, `/migrate-signer`, or `/migrate-secrets` to change them. Migration preserves the analyst public-key fingerprint and writes a signed global operational event even before the first case exists. After a credential change, active connectors may retain the previous value: type `/restart` to restart the session. Never type secrets into case text.

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
| `GCP_SERVICE_ACCOUNT_JSON` | GCS service account key for the scoped bucket. |
| `AZURE_CLIENT_SECRET` | Azure Blob service principal secret for the scoped container. |
| `IRMIND_CROWDSTRIKE_CLIENT_ID`, `IRMIND_CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike API client. |
| `IRMIND_SENTINELONE_API_TOKEN` | SentinelOne site-scoped token. |
| `IRMIND_MISP_API_KEY` | MISP read-only key. |
| `VIRUSTOTAL_API_KEY` | VirusTotal enrichment key. |

The OS backend stores signing keys under a separate `irmind` service: `local-analyst` and `local-agent-<id>` for later unattended operation. The file backend stores the same identities encrypted. Both keep private keys inside the backend; a missing configured backend blocks signing.

## Choose a model

No provider is selected by default. In the TUI, type `/model` to choose Ollama or a remote provider, select its model, optionally test the connection with synthetic text, and confirm any remote data transfer. Use `/modules` and `/edit-param` for advanced public settings. For automation, `--llm-module` and the matching environment variables override the saved selection and fields for that run.

A keyless local service may use HTTP only on loopback; HTTPS works there too. Remote endpoints require HTTPS and a destination-specific key. A different custom URL never inherits `OPENAI_API_KEY`. Select other compiled providers with their module IDs and settings in [modules](modules.md). Confirm retention, processing region, and data classification before any external connection.
