# Case budget measurements and proposed defaults

These measurements size the defaults for the v0.4.2 case budget UI. They use
synthetic bundled skill episodes and the local scripted model, with no provider
requests, credentials or transfer charges. They are counts and byte sizes, not
an ingestion throughput or execution-time benchmark.

## Reproduction and interpretation

The instrumentation is in the existing `skills_runtime` integration tests.
Set `IRMIND_SKILL_BUDGET_MEASUREMENTS` to an output directory when running that
target with all product features. The normal test suite runs the same episodes
without writing measurement files. The additional six-turn investigation uses
the same case, source and signed history for all six turns, and verifies the
case afterward.

For every model request, serialize a provider-neutral JSON object containing
messages (role, content, tool calls and call IDs), tool schemas and the output
token limit. Sum its UTF-8 byte length across all requests, including repeated
history, tool results and loaded skill text. Count model tool proposals and
signed dispatch/accounting events separately. Response-content bytes include
assistant text and argument JSON, but exclude transport framing and private
provider reasoning. No prompt, evidence text, key or machine path is published.

The scripted model does not report provider token usage. `provider_tokens` is
therefore null, not zero. `(request_bytes + response_content_bytes + 3) / 4`
(integer division) is only a planning estimate, not a tokenizer result, billing
measurement or hard-limit accounting rule. Real providers can tokenize the same
content differently and can consume reasoning tokens. The engine's actual usage
receipts and provider usage remain authoritative for token accounting.

The [machine-readable results](benchmark-data/case-budget-scripted.json) record
all 13 bundled episodes and the multi-turn case, with the production baseline
commit and measurement method. Private ground truth stays outside model
requests, tools and evidence, as checked by the existing episode tests.

## Results

| Skill / scenario | Turns | Model requests | Proposed / charged tool calls | Request JSON bytes | Planning tokens (estimate) |
| --- | ---: | ---: | ---: | ---: | ---: |
| aws-credential-compromise | 1 | 4 | 4 / 4 | 77504 | 19517 |
| aws-s3-data-exfiltration | 1 | 7 | 7 / 7 | 111101 | 27997 |
| azure-entra-identity-compromise | 1 | 7 | 7 / 7 | 119347 | 30096 |
| gcp-service-account-abuse | 1 | 7 | 7 / 7 | 114160 | 28776 |
| linux-persistence | 1 | 7 | 7 / 7 | 107402 | 27085 |
| linux-triage | 1 | 4 | 4 / 4 | 73916 | 18619 |
| linux-webshell | 1 | 7 | 7 / 7 | 107958 | 27244 |
| malware-execution-triage | 1 | 7 | 7 / 7 | 109030 | 27480 |
| network-c2-beaconing | 1 | 7 | 7 / 7 | 113160 | 28518 |
| windows-lateral-movement | 1 | 7 | 7 / 7 | 108133 | 27249 |
| windows-persistence | 1 | 7 | 7 / 7 | 107792 | 27162 |
| windows-ransomware | 1 | 7 | 7 / 7 | 110010 | 27716 |
| windows-triage | 1 | 4 | 4 / 4 | 74217 | 18695 |
| aws-s3-data-exfiltration (same-case follow-ups) | 6 | 42 | 42 / 42 | 730345 | 183916 |


## Proposed defaults and organization ceiling

Use 2,000,000 tokens and 1,000 tool calls as the requested defaults for new
cases. Keep the absolute maxima at 10,000,000 tokens and 10,000 calls. A loaded
organization policy with a lower ceiling always wins: effective case limits
are the component-wise minimum of the analyst's approved case budget and the
current organization policy. Installing this version must not rewrite a policy
file or silently raise its explicit limits. The repository example should show
the new defaults when the implementation is integrated.

The multi-turn measurement illustrates repeated context costs even with a small
source and short answers. Seven proposals in one catalog episode also explain
why 100 calls leave little room for follow-up investigation. The higher defaults
provide operating headroom; they are not evidence that real investigations
will cost a particular amount. No cloud-transfer or price recommendation can
be inferred from these entirely local runs. Retain the current object-read,
transfer-confirmation and per-case transfer limits.

## Implementation boundaries

`/settings` gains a Limits section for signed defaults for future cases.
`/budget` shows the current case's effective ceiling, consumed amounts and
remaining amounts, and opens validated analyst-only fields. An increase needs
an explicit confirmation and an Analyst-signed case operation before it becomes
effective. No agent tool can apply it. Decreases below already consumed amounts
are rejected. A stricter organization policy takes effect immediately and is
shown distinctly from the recorded case allocation. Historical consumption
never resets when a budget changes.

At 80% show a warning, and at exhaustion name the dimension, usage and effective
limit, with `/budget` guidance or an explanation that the organization ceiling
must change. Preserve the final response/summary behavior and its reserved
allowance; a final request cannot exceed the remaining token budget. If no
model request can fit, retain the work and show a local summary of completed
steps and pending work. Case tokens include repeated history, results, skill
loads and summaries. Cost is shown only when the provider/pricing information
supports it; unavailable usage is labeled, never displayed as a measured zero.

Use the existing signed operation/audit and case-lock mechanisms. This proposal
adds no port, dependency, credential or model capability. Budget changes do not
change scope, organization restrictions, tool risk or approval requirements.
Skills and future subagents consume the same case budget. Required tests cover
limits below/at/above the ceiling, 80%, exhaustion, restarts, failed signing,
model attempts to raise a budget, unchanged consumption after increases, and
scope/approval enforcement at higher budgets.
