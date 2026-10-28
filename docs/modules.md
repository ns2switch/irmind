# Modules

This page is for operators choosing a connector or keystore. Each section states what it does, the least privilege it needs, how to enable it, and what it cannot do. Store credentials as described in [configuration](configuration.md); product modules never read a keystore or environment themselves.

Modules are compiled into the binary. In the TUI, press `m` to select a compiled module, edit its public fields, and enable it; press `k` for its credentials. The changes persist and the session reloads inside the TUI. The environment variables and CLI switches below provide temporary automation overrides. Nothing is selected automatically.

## OpenAI-compatible

**Does:** Streams model responses and proposed tool calls through the OpenAI Chat Completions protocol. It supports the official API, approved compatible endpoints, and local services such as Ollama.

**Permission:** Access only to an approved model and endpoint. A local keyless service may use HTTP on loopback; HTTPS also works. Remote endpoints require HTTPS and a key dedicated to that URL.

**Configure:** Included in the standard binary. Set `IRMIND_MODEL` and optionally `IRMIND_LLM_BASE_URL`. Select `--llm-module llm-openai-compatible`. Store `OPENAI_API_KEY` in the selected secret backend only for the official URL, or `IRMIND_LLM_API_KEY` for a custom endpoint.

**Limits:** Streaming must include final usage data; incomplete streams fail closed. Pattern redaction cannot guarantee that all sensitive content is removed. Obtain provider approval before sending incident data.

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

**Does:** Searches events from one configured index and retrieves an alert record by exact ID. Both return bounded evidence. The agent submits values, not free-form SPL.

**Permission:** A dedicated read-only token with search access only to the configured index. Do not grant lookup writes, alert actions, or external output commands.

**Configure:** Build with `--features siem-splunk`. Set `IRMIND_SPLUNK_URL`, `IRMIND_SPLUNK_SOURCE_ID`, `IRMIND_SPLUNK_INDEX`, and `IRMIND_SPLUNK_ACCOUNT_FIELD`. Set optional `IRMIND_SPLUNK_ALERT_ID_FIELD` if the index uses a field other than `alert_id`. Store `IRMIND_SPLUNK_TOKEN`, then enable `--enable-splunk`. Include the source, account, and UTC window in the case scope. In the case TUI, `/siem-alert <source> <account> <alert-id> <from-UTC> <to-UTC>` retrieves one alert through the same policy and custody path as model proposals.

**Limits:** The module fixes index and time bounds server-side, caps results, requires HTTPS, and refuses unsafe or ambiguous queries. Alert lookup searches the configured index and alert ID field; it does not call a separate Splunk alert-management API. It does not expose general SPL.

The module uses Splunk's [search export endpoint](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.0/search-endpoints/search-endpoint-descriptions) and a generated [field-value search](https://help.splunk.com/en/splunk-enterprise/search/spl2-search-reference/search-command/search-command-usage).

## AWS CloudTrail and IAM

**Does:** Reads CloudTrail events and selected IAM user or role details. STS checks the actual account and role before dispatch.

**Permission:** A dedicated role with `sts:GetCallerIdentity`, `cloudtrail:LookupEvents`, and only the needed `iam:GetRole` or `iam:GetUser` reads. Keep its trust policy narrow.

**Configure:** Build with `--features cloud-aws`. Set `IRMIND_AWS_SOURCE_ID`, `IRMIND_AWS_REGION`, and `IRMIND_AWS_ROLE_NAME`. Store `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` when needed. Enable `--enable-aws` and scope the account and window.

**Limits:** One configured region and bounded queries. The module does not assume ambient AWS profiles and cannot change cloud resources.

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

## JSON and CloudTrail parser

**Does:** Indexes local JSON and CloudTrail records into the case timeline and DuckDB graph without sending them to a model.

**Permission:** Read access to the selected local file only.

**Configure:** Included and active in every binary. Use the TUI's `/ingest` picker or the [CLI ingest command](development/cli.md).

**Limits:** Each file is loaded within a 50 MB cap, then records are parsed in a stream and indexed in bounded batches. Deeply nested JSON, excessive record sets, and records with over 2,048 distinct search terms are rejected. Graph text search matches all query words rather than substrings. Searchable words are 2–64 bytes. Other log formats need future parsers.

## OS keystore

**Does:** Signs as Analyst or Agent and stores module credentials in Keychain, Credential Manager, or Secret Service.

**Permission:** Access to the current user's OS credential store. Linux Secret Service normally needs a D-Bus session.

**Configure:** Compiled by default with `keystore-os`. Choose `os` explicitly for `signer`, `secrets`, or both on first launch. Press `k` to manage credentials without displaying their values.

**Limits:** A headless SSH session may lack an unlocked OS keyring. IRMind stops if this backend is selected but unavailable; select and migrate to `file` explicitly.

## File keystore

**Does:** Signs as Analyst or Agent and stores module credentials in a local encrypted file.

**Permission:** Write access to the current user's private application-data directory; no network or graphical session is needed.

**Configure:** Compiled by default with `keystore-file`. Choose `file` explicitly for `signer`, `secrets`, or both. The TUI prompts for a passphrase without echo; use `--passphrase-fd` for CLI automation. Press `k` to change the passphrase or migrate a capability.

**Limits:** Argon2id and XChaCha20-Poly1305 protect data at rest, but a weak passphrase or a compromised user session can expose an unlocked store. Keep the public-key fingerprint outside the machine. Migration is signed in the global operational chain and requires a session restart to take effect.

## Provider contract

Contributors adding a module should use [the architecture guide](development/architecture.md) and the shared contract suite in `irmind-testkit`. Do not enable a provider by default.
