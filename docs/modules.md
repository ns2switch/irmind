# Modules

This page is for operators choosing a connector or keystore. Each section states what it does, the least privilege it needs, how to enable it, and what it cannot do. Store credentials as described in [configuration](configuration.md); product modules never read a keystore or environment themselves.

The normal binary includes every current product module and both keystores. None is enabled automatically. In the TUI, use `/settings model` to select and test an AI provider, `/settings connectors` to enable connectors and edit public fields, and `/settings keystore` for credentials. The changes persist and the session reloads inside the TUI. Use `--no-default-features --features keystore-file` for a minimal binary; at least one signer and secrets backend is required. The environment variables and CLI switches below provide temporary automation overrides.

Splunk, MISP, CrowdStrike, SentinelOne, and S3-compatible storage can use a connector-specific CA PEM in `/settings connectors`. IRMind signs the file fingerprint in the non-secret configuration, checks it at startup, and adds that CA to system roots without disabling hostname verification. See [configuration](configuration.md#non-secret-settings).

## OpenAI-compatible

**Does:** Streams model responses and proposed tool calls through the OpenAI Chat Completions protocol. It supports the official API, approved compatible endpoints, and local services such as Ollama.

**Permission:** Access only to an approved model and endpoint. A local keyless service may use HTTP on loopback; HTTPS also works. Remote endpoints require HTTPS and a key dedicated to that URL.

**Configure:** Included in the standard binary. Set `IRMIND_MODEL` and optionally `IRMIND_LLM_BASE_URL`. Select `--llm-module llm-openai-compatible`. Store `OPENAI_API_KEY` in the selected secret backend only for the official URL, or `IRMIND_LLM_API_KEY` for a custom endpoint.

**Limits:** Streaming must include final usage data; incomplete streams fail closed. Pattern redaction cannot guarantee that all sensitive content is removed. Obtain provider approval before sending incident data.

The `/settings model` presets below use this same module. Their listed base URLs are defaults, not a license to send incident data. Chat Completions, streaming, and tool calling are documented by each provider; actual tool support still depends on the chosen model. The local services must be running and configured for tool capable models. Listing models is optional; enter a model ID manually if a service does not expose a compatible list.

| Preset | Default base URL | Provider documentation |
| --- | --- | --- |
| OpenAI | `https://api.openai.com/v1/` | [Chat Completions](https://platform.openai.com/docs/api-reference/chat/create) |
| Mistral | `https://api.mistral.ai/v1/` | [API reference](https://docs.mistral.ai/api/) |
| Groq | `https://api.groq.com/openai/v1/` | [API reference](https://console.groq.com/docs/api-reference) |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai/` | [OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai/) |
| xAI | `https://api.x.ai/v1/` | [Chat Completions](https://docs.x.ai/developers/rest-api-reference/inference/chat-completions) |
| Together | `https://api.together.ai/v1/` | [OpenAI compatibility](https://docs.together.ai/docs/inference/openai-compatibility) |
| Ollama | `http://127.0.0.1:11434/v1/` | [OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility) |
| LM Studio | `http://127.0.0.1:1234/v1/` | [OpenAI compatibility](https://lmstudio.ai/docs/developer/openai-compat) |
| vLLM | `http://127.0.0.1:8000/v1/` | [OpenAI-compatible server](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/) |

Azure OpenAI endpoints that require an `api-version` query parameter are not supported by the URL form. A custom endpoint is available, but it must meet the same streaming, tool calling, and bounded response requirements.

## Anthropic

**Does:** Uses the native Messages API and streams text, tool proposals, and usage.

**Permission:** An API account allowed to invoke the approved model.

**Configure:** Build with `--features llm-anthropic`, set `IRMIND_ANTHROPIC_MODEL`, store `ANTHROPIC_API_KEY` in the selected secret backend, and select `--llm-module llm-anthropic`.

**Limits:** The endpoint is remote HTTPS. Confirm region, retention, and contractual data handling before use.

## DeepSeek

**Does:** Uses the shared Chat Completions adapter for DeepSeek.

**Permission:** An API account allowed to invoke the approved model.

**Configure:** Build with `--features llm-deepseek`, set `IRMIND_DEEPSEEK_MODEL`, store `DEEPSEEK_API_KEY`, and select `--llm-module llm-deepseek`.

**Limits:** Remote HTTPS and final stream usage are required; provider approval is separate from module availability.

## OpenRouter

**Does:** Uses the shared Chat Completions adapter for the selected OpenRouter model.

**Permission:** An API account limited to the models approved by your organization.

**Configure:** Build with `--features llm-openrouter`, set `IRMIND_OPENROUTER_MODEL`, store `OPENROUTER_API_KEY`, and select `--llm-module llm-openrouter`.

**Limits:** Model routing may change the actual data processor. Review the selected model and retention policy before use.

## Splunk

**Does:** Searches approved event fields in one configured index and retrieves an alert record by exact ID. Both return bounded evidence. The agent submits structured fields and values, never SPL.

**Permission:** A dedicated read-only token with search access only to the configured index. Do not grant lookup writes, alert actions, or external output commands.

**Configure:** Build with `--features siem-splunk`. Set `IRMIND_SPLUNK_URL`, `IRMIND_SPLUNK_SOURCE_ID`, `IRMIND_SPLUNK_INDEX`, and `IRMIND_SPLUNK_ACCOUNT_FIELD`. Set optional `IRMIND_SPLUNK_ALERT_ID_FIELD` if the index uses a field other than `alert_id`. The search fields default to `eventName`, `user`, `sourceIPAddress`, and `host`; use `IRMIND_SPLUNK_EVENT_NAME_FIELD`, `IRMIND_SPLUNK_USER_FIELD`, `IRMIND_SPLUNK_SOURCE_IP_FIELD`, and `IRMIND_SPLUNK_HOST_FIELD` to match your index. Store `IRMIND_SPLUNK_TOKEN`, then enable `--enable-splunk`. Include the source, account, and UTC window in the case scope. In the case TUI, `/siem-alert <source> <account> <alert-id> <from-UTC> <to-UTC>` retrieves one alert through the same policy and custody path as model proposals.

**Limits:** The model can compare only `event_name`, `user`, `source_ip`, or `host` using `eq`, `not_eq`, or `prefix`. It can request raw events, `count_by`, `top`, or `distinct` on one of those fields, with at most 20 results. The module fixes the index and a window of at most 24 hours on the server, escapes quotes and backslashes in values, rejects SPL control characters, requires HTTPS, and disables redirects. Alert lookup searches the configured index and alert ID field; it does not call a separate Splunk alert-management API. Existing pending calls with the old free-form `query` argument are denied; historical signed entries still verify.

The module uses Splunk's [search export endpoint](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.0/search-endpoints/search-endpoint-descriptions) and a generated [field-value search](https://help.splunk.com/en/splunk-cloud-platform/search/search-reference/10.6/search-commands/search).

## AWS CloudTrail and IAM

**Does:** Reads CloudTrail events and selected IAM user or role details. STS checks the actual account and role before dispatch.

**Permission:** A dedicated role with `sts:GetCallerIdentity`, `cloudtrail:LookupEvents`, and only the needed `iam:GetRole` or `iam:GetUser` reads. Keep its trust policy narrow.

**Configure:** Build with `--features cloud-aws`. Set `IRMIND_AWS_SOURCE_ID`, `IRMIND_AWS_REGION`, and `IRMIND_AWS_ROLE_NAME`. Store `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` when needed. Enable `--enable-aws` and scope the account and window.

**Limits:** One configured region and bounded queries. The module does not assume ambient AWS profiles and cannot change cloud resources.

## Cloud object storage (S3, GCS, Azure Blob)

**Does:** Lists versioned objects under a case-scoped prefix and reads selected exported logs in bounded streams. IRMind hashes the downloaded bytes and converts accepted records to local Parquet. It never writes to the bucket or container.

**Permission:** S3 needs `s3:ListBucket` limited to the prefix and `s3:GetObject`; GCS needs `roles/storage.objectViewer` on the selected bucket; Azure needs `Storage Blob Data Reader` on the selected container. Use dedicated identities and deny writes in the cloud policy as well as IRMind. Provider ETags are version guards, not evidence hashes.

**Configure:** Build with `--features storage-s3`, `storage-gcs`, or `storage-azure`. In the TUI's module view, enable each compiled connector explicitly and set its source ID and bucket or container. S3 also needs a region; Azure needs account, client ID, and tenant ID. Optional endpoint overrides must use HTTPS. Add the matching object prefix and UTC window to the case and organization policy scope.

**Credentials:** S3 reuses the dedicated `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN` from the selected secret backend. GCS uses `GCP_SERVICE_ACCOUNT_JSON` with the service account private key. Azure uses `AZURE_CLIENT_SECRET` for the configured service principal. These values never belong in `config.toml` or environment variables.

**Use in the TUI:** Run `/objects <source> <s3|gs|az> <bucket-or-container> <prefix> <from-UTC> <to-UTC>` to list up to 20 objects and see the estimated bytes. Narrow a truncated listing. Run `/object-read <number>` to confirm the selected version and transfer. Add `--copy-original` to keep an explicit local original. The activity indicator shows transferred bytes and elapsed time; Esc or `/pause` cancels. A repeated read checks an already signed original against its manifest.

**Limits:** Reads require a complete signed listing of the exact object and version, a per-read byte ceiling, and the case transfer budget. A listing page over 8 MiB is rejected before parsing. Above `object_transfer_approval_bytes`, a second signed analyst approval is required. Failed transfers consume their reserved budget. Cloud bytes are spooled once into a private temporary directory and removed after local conversion. A repeated read in an open case rechecks the signed original and may incur provider charges. For offline verification after sealing, explicitly retain a local copy before sealing. No ambient cloud profiles, CLI sessions, or instance credentials are used. `object_store` exposes ETags but not a portable native provider checksum; the manifest records the ETag as an opaque version guard and signs IRMind's own SHA-256.

## CrowdStrike

**Does:** Reads host inventory and host-linked alerts.

**Permission:** `hosts:read` and `Alerts: READ` for a dedicated API client.

**Configure:** Build with `--features edr-crowdstrike`. Set `IRMIND_CROWDSTRIKE_URL` and `IRMIND_CROWDSTRIKE_SOURCE_ID`. Store `IRMIND_CROWDSTRIKE_CLIENT_ID` and `IRMIND_CROWDSTRIKE_CLIENT_SECRET`. Enable `--enable-crowdstrike` and scope the exact host.

**Limits:** No verified general process-tree API is exposed. Ambiguous hosts, cross-host alerts, missing scope fields, redirects, and oversized responses fail closed.

## SentinelOne

**Does:** Reads endpoint details, detections, and process descendants associated with a specific threat.

**Permission:** Site-scoped `Endpoints.view` and `Threats.view` access.

**Configure:** Build with `--features edr-sentinelone`. Set `IRMIND_SENTINELONE_URL`, `IRMIND_SENTINELONE_SOURCE_ID`, and `IRMIND_SENTINELONE_SITE_ID`. Store `IRMIND_SENTINELONE_API_TOKEN`. Enable `--enable-sentinelone` and scope the exact host.

**Limits:** Process data is limited to a verified threat's Explore events; it is not an arbitrary host process search.

## MISP

**Does:** Looks up IOCs in an internal threat-intelligence service.

**Permission:** A read-only MISP API key with access only to the approved event set.

**Configure:** Build with `--features ti-misp`. Set `IRMIND_MISP_URL` and `IRMIND_MISP_SOURCE_ID`. Store `IRMIND_MISP_API_KEY`, enable `--enable-misp`, and include that source in the case scope.

**Limits:** Exact, bounded lookup only. The configured MISP instance must be internal and HTTPS.

## VirusTotal

**Does:** Enriches a public hash, domain, or eligible public IPv4 address through an external service.

**Permission:** A dedicated API key and explicit analyst approval for each external lookup.

**Configure:** Build with `--features ti-virustotal`, store `VIRUSTOTAL_API_KEY`, and enable `--enable-virustotal`.

**Limits:** An external lookup can reveal that an IOC is being investigated. Internal or ambiguous addresses are rejected; approval is required even for valid IOCs.

## Streaming JSON and exported cloud log parser

**Does:** Parses generic JSON, AWS CloudTrail, GCP Cloud Audit Logs, Azure Activity, and Entra ID sign-in exports in bounded streams. Large cases become partitioned Parquet. Bounded Arrow scans read only signed, hash-checked IRMind artifacts. The parser does not send records to a model.

**Permission:** Read access to the selected local file only.

**Configure:** Included and active in every binary. Use the TUI's `/ingest` picker or the [CLI ingest command](development/cli.md).

**Limits:** Deeply nested JSON and oversized individual records are rejected. Originals are hashed in place; copying one requires an explicit choice. Parquet searches use bounded substring matching and optional date, account or project, and region filters. Older derived indexes must be migrated from copied originals before graph queries are available. Other log formats need future parsers.

## OS keystore

**Does:** Signs as Analyst or Agent and stores module credentials in Keychain, Credential Manager, or Secret Service.

**Permission:** Access to the current user's OS credential store. Linux Secret Service normally needs a D-Bus session.

**Configure:** Compiled by default with `keystore-os`. Choose `os` explicitly for `signer`, `secrets`, or both on first launch. Use `/settings keystore` to manage credentials without displaying their values.

**Limits:** A headless SSH session may lack an unlocked OS keyring. IRMind stops if this backend is selected but unavailable; select and migrate to `file` explicitly.

## File keystore

**Does:** Signs as Analyst or Agent and stores module credentials in a local encrypted file.

**Permission:** Write access to the current user's private application-data directory; no network or graphical session is needed.

**Configure:** Compiled by default with `keystore-file`. Choose `file` explicitly for `signer`, `secrets`, or both. The TUI prompts for a passphrase without echo; use `--passphrase-fd` for CLI automation. Use `/settings keystore` to change the passphrase or migrate a capability.

**Limits:** Argon2id and XChaCha20-Poly1305 protect data at rest, but a weak passphrase or a compromised user session can expose an unlocked store. Keep the public-key fingerprint outside the machine. Migration is signed in the global operational chain and requires a session restart to take effect.

## Provider contract

Contributors adding a module should use [the architecture guide](development/architecture.md) and the shared contract suite in `irmind-testkit`. Do not enable a provider by default.
