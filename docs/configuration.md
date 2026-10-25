# Configuration

This page is for operators setting up a controlled evaluation. It explains case scope, policy, non-secret settings, and the keyring. For individual connector permissions, see [modules](modules.md).

## Case scope

A case can remain local-only. To permit remote reads, set an explicit source, target, and UTC window. The current wire format is:

```text
v1;sources=splunk-demo;accounts=000000000000;hosts=demo-host;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z
```

Use comma-separated values within `sources`, `accounts`, and `hosts`. The TUI's new-case form and `/scope` command edit the scope; the change is signed. Queries outside it require approval or are denied. A free-text legacy scope grants no remote access. Project IDs are not supported in this format yet.

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

The composition root reads these environment variables. Set only values that match your approved endpoint and case scope.

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

## Keyring accounts

Do not set credential values in environment variables. Add each module credential to the native keyring with service `irmind-module` and the account name below. Use your system's keyring manager; IRMind does not display secrets.

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

Signing keys use a separate `irmind` service: account `local-analyst` and, for later unattended operation, `local-agent-<id>`. The application creates these keys in the keyring. There is no file fallback. If the keyring fails, signing stops; `verify-export` can still check a package without it.

## Choose a model

No provider is selected by default. The OpenAI-compatible module is compiled in but must be selected:

```sh
IRMIND_MODEL=YOUR_LOCAL_MODEL IRMIND_LLM_BASE_URL=http://127.0.0.1:11434/v1/ \
  ./target/release/irmind --llm-module llm-openai-compatible
```

A keyless local service may use HTTP only on loopback; HTTPS works there too. Remote endpoints require HTTPS and a destination-specific key. A different custom URL never inherits `OPENAI_API_KEY`. Select other compiled providers with their module IDs and settings in [modules](modules.md). Confirm retention, processing region, and data classification before any external connection.
