# Configuration

This page is for operators setting up a controlled evaluation. It explains case scope, policy, non-secret settings, and keystore selection. For connector permissions, see [modules](modules.md).

## Model output

IRMind does not impose an output-token allowance on the main agent, subagents,
summaries or compaction. Adapters send the selected model's native output maximum
when known. Unknown optional maxima are omitted; an API requiring an unknown
maximum fails before dispatch and points to `/settings model`.

In `/settings model`, select **Model output profile** in the model review. Enter
the model's documented native output maximum and whether the compatible/local API
requires that parameter. Empty means unknown. These are signed non-secret module
settings, `IRMIND_MODEL_MAX_OUTPUT_TOKENS` and, for compatible APIs,
`IRMIND_MODEL_OUTPUT_REQUIRED`. They describe capabilities, not a smaller response
budget. **Test connection** uses the current, unsaved draft, including its output
maximum; probing does not persist settings or credentials or sign a configuration
operation. Exact built-in profiles apply only to their documented provider endpoint;
a local model with the same name does not inherit them.

A positive case balance admits a request. Its complete response and actual reported
usage are retained even if they exceed that balance; the excess is visible in the
recorded usage. No further request starts at an exhausted balance. Use `/budget`
to review or increase the signed allocation within the organization ceiling.
Children reserve their input bound plus the known model maximum before dispatch.
An unknown maximum or an insufficient child slice prevents that request from
starting. In-flight calls are not cut short to fit a remaining token allowance.

A provider `length`/`max_tokens` stop is labelled **The model reached its maximum
output**. IRMind attempts one tool-free continuation when budget and rounds permit,
using one continuous answer card and accounting for both calls. A second native
stop does not start another retry. `/continue` is for round or budget exhaustion.

Existing security bounds remain: 2,000,000 stream bytes, 1,000,000 bytes per guard
input and a 1 MiB signed frame, including encoding and metadata. If text cannot
fit, the retained UTF-8 prefix explicitly says **Truncated by IRMind's security
limit**. Tokens and bytes are not equivalent. The parent receives a child summary
of at most 16 KiB; complete in-frame child text belongs in the signed branch.
Cancellation, deadlines, malformed provider responses and resource failures remain
explicit interruptions.

Native specifications: [OpenAI models](https://developers.openai.com/api/docs/models),
[DeepSeek limits](https://api-docs.deepseek.com/quick_start/pricing/),
[Anthropic models](https://platform.claude.com/docs/en/models/overview), and
[OpenRouter parameters](https://openrouter.ai/docs/api_reference/parameters).
Unknown models use omission or an analyst-declared maximum; context length is not
an output maximum.

## Case scope

A case can remain local-only. To permit remote reads, the TUI's new-case form asks for sources, accounts, projects, hosts, object prefixes, and a UTC start and end time. An object prefix looks like `s3://audit-bucket/AWSLogs/123/CloudTrail/`, `gs://bucket/export/`, or `az://container/export/`. Add one with `/scope add object <URI>`; the source ID must also be in the case scope. Other targets use `/scope add project <id>` (or `source`, `account`, `host`). Widen the window with `/scope window <from> <to>`. Changes are signed by the analyst. Object reads outside the case or organization prefix are denied. The automation encoding is documented in the [CLI reference](development/cli.md).

## Policy file

Pass `--policy policy.toml` or set `IRMIND_POLICY`. The repository's [policy.toml](../policy.toml) is a versioned example:

```toml
version = 1
max_tool_calls_per_case = 1000
max_model_rounds_per_turn = 25
max_model_result_bytes = 10000
max_model_tokens_per_case = 2000000
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

`max_model_rounds_per_turn` defaults to 25 if omitted and cannot exceed 100. At the limit, IRMind requests a final summary without tools and offers `/continue`. Tool-call and token limits still apply across the case.

## Case allocations and consumption

There are two levels. `policy.toml` is the organization ceiling; an analyst
cannot exceed it from the TUI, through an approval, or through a skill.
`/settings limits` chooses signed defaults for **future cases**. `/budget` in
an open case shows its allocation, current organization ceiling and consumption,
and edits its token, tool-call and reserved cloud-byte allocations. Fields are
prefilled; Tab changes fields, Enter reviews, then arrows or a number followed
by Enter explicitly confirm the Analyst signature. Escape cancels. Increasing a
case allocation requires this confirmation. The consumed amounts never reset.
A sealed case cannot change its allocation. A stricter policy immediately
reduces the effective ceiling of an existing allocation.

The defaults are 2,000,000 model tokens and 1,000 tool calls, clipped to any
smaller organization ceiling. Fixed supported maxima stay 10,000,000 tokens and
10,000 calls. Cloud limits and transfer approvals retain their previous values.
Existing policy files are never rewritten. Local scripted
[measurements](https://github.com/ns2switch/irmind/blob/a0dcfd1/docs/development/case-budget-measurements.md)
cover all 13 bundled skills and a six-turn case; their byte-based planning
estimates are not provider billing measurements.

At 80% the status line warns and points to `/budget`. At exhaustion the turn
preserves its results and finishes with a summary and the consumed/effective
limits. The normal limit path uses a tool-free summary when tokens remain. If no
tokens remain, or history compaction has no remaining token balance, IRMind
shows a local summary without another model request. Review `/budget` before
`/continue`, or ask the organization administrator if its ceiling prevents an
increase. The model cannot apply allocation changes.

Provider usage arrives after each request; a final receipt can cross an
allocation before further calls stop. Provider-side account caps remain useful
for billing.

Tokens include every provider-reported input and output: repeated conversation
history, tool results, loaded skill text, compaction and final summaries. Missing
provider usage is explicitly unavailable, with any reported subtotal shown as
a lower bound. It is never presented as a measured zero. Cost appears only
when usage and configured pricing support the estimate. Tool calls include
signed dispatches and bounded skill reads. Cloud bytes are **reservations** from
signed object-read dispatches, including failed/canceled transfers, as in budget
enforcement; they are not a claim of exact network traffic.

Non-secret defaults are stored in `config.toml`, for example:

```toml
[case_budget_defaults]
model_tokens = 2000000
tool_calls = 1000
cloud_bytes = 536870912000
```

The initial allocation is signed atomically with case creation. Later changes
are Analyst-signed case records; changing defaults does not alter existing cases.
A case without an initial allocation asks for explicit confirmation through
`/budget` before new model/tool work. This appends a signed allocation and keeps
all previously recorded consumption; it does not rewrite evidence or reset usage.
Opening a case or changing defaults never initializes its allocation silently.

## Non-secret settings

The TUI stores non-secret settings in `config.toml` in the [standard data directory](platforms.md#data-and-terminal-behavior). The normal build compiles all current product modules and both keystores but enables none. `/settings` opens five sections: model, connectors, keystore, preferences, and limits. `/settings model` opens one directly. In connectors, arrows select a module, Tab selects a parameter, and Enter edits it in a visible field. The first typed or pasted character replaces the displayed default; Enter accepts it and Ctrl+U clears it. A URL is trimmed and repeated path slashes are collapsed before validation. Credentials use masked fields in the keystore section. The session reloads inside the TUI after a change. Activation or endpoint changes that may send data off this computer require explicit signed confirmation. A minimal build uses `--no-default-features --features keystore-file` because a signer and secrets backend must remain available.

For Splunk, MISP, CrowdStrike, SentinelOne, and an S3-compatible storage endpoint, `/settings connectors` also accepts an optional CA PEM file. IRMind shows and signs its SHA-256 fingerprint alongside the path. The PEM augments the operating system trust roots; TLS hostname checks remain enabled. The file is read again and its hash checked when the connector starts, so replacing it requires another approval. Clear the path to remove the connector-specific CA. Do not put a private key in this file.

`resume_last_case` and `show_hints` default to `true`. After startup, the TUI reopens the most recently used open case only if its custody chain verifies. Sealed or deleted cases stay on the home screen; a verification failure appears there as a warning. Use `/settings preferences` to change resumption, context hints, mouse capture, or the `auto`, `light`, or `dark` theme. The private `last-case` reference is stored beside `config.toml` and is not part of custody. CLI automation does not resume a case.

Use **Maximum parallel workers** in `/settings preferences` to cap local source decoding and parallel Parquet scans. Leave it blank to use one fewer worker than the available logical CPUs, with at least one worker. An explicit `max_parallel_workers` value (1–256) can use all available CPUs. The local memory budget may reduce the effective count further. This signed preference applies when the session reloads. It does not change source order or artifact boundaries.

### Declarative status bar

Open **Status bar** in `/settings preferences`. Choose the **Minimal**,
**Investigation** (default), or **Costs** preset, then enable segments, move them
earlier or later, choose a priority from 0 to 100 and a theme color, and edit the
separator. The live preview uses clearly labeled example values; only **Save and
sign** commits the template as a global signed configuration operation. **Restore
default** also remains a preview until saved. Esc leaves without saving.

The closed segment list is: case title, severity, seal state, model, provider,
tokens used, token budget, token percentage, cache tokens read and written, tool
calls and their budget, cloud bytes and their budget, estimated cost, active
subagents, pending approvals, detections, ingested sources, signing/secrets
keystore profile, data directory, IRMind version, UTC clock, and activity.
Unavailable cache counters are labeled unavailable; unpriced cost is omitted,
never estimated as zero. Cache counters become available only when provider accounting
supports them. Model usage and budgets retain their existing accounting rules.

The order in the template is the display order. At narrow widths, including 80
columns, segments with the lowest priority disappear first; equal priorities
keep the earlier segment. The last remaining segment is shortened with an
ellipsis if necessary. Case titles and other external text are escaped for the
terminal, theme colors respect `NO_COLOR`, and scope/budget warnings remain
visible independently of the chosen template.

The optional `status_bar` configuration has `version = 1`, a separator of at
most four printable characters, and at most one entry for each segment. Colors
come from the closed theme set: `text`, `muted`, `accent`, `warning`, `error`,
`success`. Unknown segment names, duplicate entries and control characters are
rejected. The template does not execute scripts, shell commands or external
programs.


For automation, resolution order is **CLI flag > environment variable > config.toml > default**. An override lasts only for that run; the TUI does not silently replace it. The file contains module IDs, models, URLs, source IDs, indexes, regions, and optional pricing, but never credentials or passphrases. Unknown or secret manifest fields fail validation. Example:

```toml
version = 1
llm_module = "llm-openai-compatible"
mouse_capture = false # optional: leave terminal text selection available
resume_last_case = true # optional: reopen the last verified open case
show_hints = true # optional: show guidance for empty cases and pending approvals
theme = "auto" # optional: auto, light, or dark

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
| `IRMIND_THEME`, `NO_COLOR` | Override the TUI theme (`light` or `dark`), or disable color for the session. |
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

Type `/settings keystore` to view active backends and credential presence. Select an action with Tab, arrows, and Enter to add or delete a credential, change the file passphrase, migrate a backend, or restart the session. Migration preserves the analyst public-key fingerprint and writes a signed global operational event even before the first case exists. After a credential change, active connectors may retain the previous value; choose Restart session in that section. Never type secrets into case text.

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

No provider is selected by default. In the TUI, type `/settings model` to choose a preset, enter or accept its URL, choose a listed model or enter an ID manually, and optionally test the connection with synthetic text. For a remote provider, the model list or test requires an explicit confirmation before the API key is sent. Enabling it for case data requires a separate signed confirmation. Use `/settings connectors` for advanced public settings. For automation, `--llm-module` and the matching environment variables override the saved selection and fields for that run.

The local presets are Ollama (`127.0.0.1:11434`), LM Studio (`127.0.0.1:1234`), and vLLM (`127.0.0.1:8000`). Remote presets are OpenAI, Anthropic, DeepSeek, OpenRouter, Mistral, Groq, Google Gemini's OpenAI-compatible endpoint, xAI, and Together. The latter five use the existing OpenAI-compatible module; no extra product module is needed. Model listing may be unavailable on a compatible service; the form still accepts a model ID. Tool support depends on the chosen model, and the connection test checks only basic access. Azure OpenAI endpoints requiring an `api-version` query parameter are not supported by this URL field.

A keyless local service may use HTTP only on loopback; HTTPS works there too. Remote endpoints require HTTPS and a destination-specific key. A different custom URL never inherits `OPENAI_API_KEY`. Select other compiled providers with their module IDs and settings in [modules](modules.md). Confirm retention, processing region, and data classification before any external connection.

## Source time for classic syslog

RFC 3164 time settings belong to an ingestion, not config.toml. Confirm the year, fixed UTC offset and rollover choice in the ingestion form. You may apply one confirmed choice to all files or choose separately. Retired global time fields require explicit signed removal at startup. Previously signed sources keep their recorded interpretation. See [parsers](parsers.md#legacy-syslog-time) and the [automation reference](development/cli.md).

## Common event storage

CLI ingestion, the TUI and the demo use the same source decoder, selected mapping and direct V3 writer. There is no writer preference. Each source records its decoder, mapping profile and mapping receipt in the signed case chain. JSON/cloud JSON, ECS, OCSF, EVTX, Linux, syslog, DFIR tool output, network logs and declarative definitions use this pipeline.

A mapping may preserve searchable fields and entities without classifying an event. Missing categories, outcomes and roles are not inferred from message text. New mappings apply to new ingestions. Pre-1.0 formats may change without migration; retain the creating version or re-ingest verified originals into a new case. No model or connector is enabled by the storage format.

## Local skills

`/skills` manages installations and activation through signed global operations, separate from `config.toml`. The preview shows package hashes, tools and resources before signing. No automatic download or additional credential is involved. You can inspect the 13 included methods without a model. See the [skills guide](skills.md).

## Subagent plan confirmation

In `/settings preferences`, **Confirm all subagent plans** defaults to off.
Plans at or below 25% of both remaining tokens and calls start after their preview
is displayed. Above either threshold, Start always requires the Analyst signature.
Turning this preference on requires Start for every plan. The preference change
is a signed global operation; model tools cannot change it. See
[parallel investigations](subagents.md) for task cancellation, shared budgets
and partial-result coverage.

## Case deletion audit

Use `/case delete` for a typed, Analyst-signed confirmation of an unsealed case.
`/cases deleted` shows the retained global tombstones and pending cleanup. Sealed
cases and cases open in another process cannot be deleted. See [cases](cases.md)
for ownership, interrupted cleanup, shared evidence and logical-erasure limits.

### Prompt-cache accounting

`/budget` separates ordinary input, cache reads, cache writes and output. Input
includes all these input components exactly once: a cache hit never increases a
case or child budget. Missing metadata is unavailable; partial reporting is labeled.
OpenAI and DeepSeek cache automatically. Native Anthropic requests mark only the
trusted system block and the last currently allowed tool with five-minute cache
breakpoints. Compatible and local endpoints receive no cache controls. Each turn
still has a fresh untrusted-content nonce.

Optional `cache_read_microusd_per_million` and `cache_write_microusd_per_million`
prices supplement the ordinary input/output prices in signed configuration. Write
pricing applies only to five-minute writes. Every nonzero component needs its
configured rate; unknown breakdown/lifetime or any unpriced request makes the
total estimate unavailable. Counters are provider reports, not an invoice. The
cache status segments show reported counts (with partial coverage) or unavailable.

## Source queries

Source queries start disabled. The organization supplies a `[source_queries]`
section in the policy passed to `--policy`. Its `case_ceiling` limits billed scan
bytes, retained rows and retained bytes independently of object transfer bytes.
Each `sources` entry defines the provider resource, dataset, time window,
approval threshold and per-query limits.

Use Settings → Keystore to manage the provider fields. Athena uses the existing
AWS access key, secret key and optional session token fields. BigQuery shows
`query-bigquery/<source>/service-account-json`. Azure Log Analytics shows
`query-azure-log-analytics/<source>/tenant-id`, `client-id` and `client-secret`.
The policy describes resources and limits. Keep provider credentials in the
keystore.

An analyst adopts an organization source and allocates resources to a case
through signed operations. The following commands use synthetic identifiers:

```sh
irmind --policy policy.toml source-query adopt synthetic-audit
irmind --policy policy.toml source-query allocate "$CASE_ID" \
  --scan-bytes 67108864 --retained-rows 2000 --retained-bytes 4194304 \
  --reason 'Review the scoped audit window'
```

An Analytics-only allocation uses `--allow-analytics` and can omit
`--scan-bytes`. `/budget` shows the used and reserved amounts for billed scan
bytes, retained rows and retained bytes, separately from ordinary object
transfers. The status bar's **Costs** preset includes three corresponding
segments. Add or reorder them under **Settings → Preferences → Status bar**.
The billed scan segment appears for allocations with a scan budget.

When exact-plan consent is required, in the case
use `/source-query show <plan-id>` followed by `/source-query approve <plan-id>`
after reviewing the scope, limits and translated query.

Use the retained capture for local timeline, search and entity queries. If a
capture hits its row limit, narrow the time range or add structured filters
before proposing another remote acquisition.

See [Manual validation of source queries](development/source-query-validation.md)
for an optional analyst-run exercise with each provider.

### Athena

Use a dedicated workgroup with enforced settings and a per-query scan cutoff.
Set the workgroup and the explicit cutoff-overrun acknowledgement in the
source policy. Configure the partitioned CloudTrail table and give the query
identity access only to the adopted workgroup, source data and its result
location. [Workgroup and billed-byte configuration](../crates/modules/query-athena/README.md) · [IAM actions by resource](development/source-queries-design.md#4-credentials-scope-and-minimum-permissions).

### BigQuery

Create a Cloud Logging sink to a dedicated BigQuery dataset. Declare its
timestamp-partitioned or daily-sharded layout in the source and grant the
query service account access to the selected dataset and job creation in the
query project. Store the service-account JSON in IRMind's keystore.
[Sink, layout and service-account configuration](../crates/modules/query-bigquery/README.md).

### Azure Log Analytics

Create a single-tenant Microsoft Entra app registration for client credentials.
Store the tenant ID, application client ID and client secret in IRMind's
keystore. Specify the subscription, resource group, workspace name, workspace
ID and Analytics table in the source policy.
[Microsoft Entra app and API authentication](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api).

Scope the app's service-principal grants to the adopted workspace. The adapter
needs `Microsoft.OperationalInsights/workspaces/read` and
`Microsoft.OperationalInsights/workspaces/tables/read` for the two metadata
checks. Grant `Microsoft.OperationalInsights/workspaces/query/read` and
restrict data access to the adopted tables using table-level permissions or
a granular RBAC assignment. No log ingestion, role changes, shared keys or
workspace administration permissions are required.
[Workspace and table access](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access) · [Granular RBAC](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/granular-rbac-log-analytics) · [Table plan permissions](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-table-plans).
