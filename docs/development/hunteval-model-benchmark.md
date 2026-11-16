# Manual multi-model HuntEval benchmark

This is an opt-in development harness for [#95](https://github.com/ns2switch/irmind/issues/95),
not a published model ranking. No provider calls run in CI. The 18 normalized public
episodes are pinned by commit and [per-file SHA-256](../../scripts/hunteval.sha256).
Expected answers remain outside the case, tools and model context.

## Configure and review first

Use a verified current binary. For each model, create a separate disposable IRMind
home in the TUI and explicitly configure it in `/settings model`, including data
egress approval and its SecretBackend key. Close the TUI before the benchmark.
Do not use a live investigation home. Configure prices if you want an estimate;
missing prices or usage stay unavailable, never zero. No provider key is passed
in environment variables, command arguments or a repository file.

Clone `https://github.com/ns2switch/hunteval` into a separate data directory and
check out `4cbb555a56bc17cb03b988ad2f15b1374eecf183`. The harness verifies the
checkout and source checksums before any run. Only `source/events.json` is ingested.
A private local models file contains **non-secret** metadata and data-directory
references, for example:

```json
{"models":[
  {"label":"deepseek-evaluation","module":"llm-deepseek","model":"EXACT_SAVED_MODEL_ID","revision":"provider revision if known","home":"DISPOSABLE_CONFIGURED_HOME"},
  {"label":"local-evaluation","module":"llm-openai-compatible","model":"EXACT_SAVED_MODEL_ID","revision":"local model digest if known","home":"SECOND_CONFIGURED_HOME"}
]}
```

The declared module/model must match its signed saved configuration; this harness
does not rewrite model settings. A revision is operator-reported; record unknown
rather than guessing a version behind a provider alias.

```sh
python3 scripts/hunteval_benchmark.py --hunteval-root <checkout> --models <private-models.json> --binary <verified-irmind> --output <new-results-directory>
```

The default is a dry plan with no calls or private-answer reads. Add the execution option shown below
only after reviewing its potential billable 18 × model-count runs. It asks once
per home for a file-keystore passphrase, passed privately through stdin (descriptor
0); leave blank only for OS-only backends. Provider keys are resolved solely by
IRMind's existing keystore. No automatic approvals or Analyst confirmations are
made. Execution is sequential: one root-agent CLI turn per episode, using the
same prompt. It measures that workflow, not interactive subagent orchestration.

```sh
python3 scripts/hunteval_benchmark.py --hunteval-root <checkout> --models <private-models.json> --binary <verified-irmind> --output <new-results-directory> --execute
```

## Pilot, duration and cost planning

Start with one episode per cloud before authorizing all eighteen. Repeat
the episode-selection option to select a unique subset; selection stays in pinned corpus order.
Review the dry plan first, then add the execution option only for the explicitly selected
pilot. Defaults still run all eighteen; a pilot report states its coverage as
3/18 and never represents a complete benchmark.

```sh
python3 scripts/hunteval_benchmark.py --hunteval-root <checkout> --models <private-models.json> --binary <verified-irmind> --output <new-pilot-directory> --episode aws-iam-001 --episode azure-iam-001 --episode gcp-iam-001
```

For each model, use its pilot rows to estimate a full run:

| Quantity | Illustrative extrapolation from three completed pilot episodes |
| --- | --- |
| Runtime | Six times the sum of their `elapsed_seconds`; also inspect 18 times the minimum/maximum episode time. |
| Provider cost | Six times the sum of `estimated_cost_microusd`, divided by 1,000,000 for USD, only if every row has complete usage and configured prices. |
| Known limitations | Tool rounds, failures, reasoning, prefix caches, input sizes, prices and provider aliases can change between episodes. The extrapolation is neither a cap nor a guarantee. |

If a request failed or usage/prices are unknown, record the cost as unavailable.
Do not infer zero from a local endpoint or missing invoice fields. No commercial
calls were made to prepare this guide, so it contains no invented model-specific
price or duration. Retain actual model/revision/date and pilot rows when recording
an estimate. Each episode creates its own case; review case allocations and the
organization ceiling before any full run. Paid answers may overdraw their case
allocation at request completion; the next request stays blocked, as documented.

## Output and interpretation

`report.json`, `report.md` and `SHA256SUMS` contain the corpus commit, actual binary
version/hash, UTC run timestamp, configured model ID and declared revision, per-case
status, latency, calls, reported input/output tokens and estimated microUSD cost.
Unknown or incomplete usage is explicitly marked. Failures remain rows; invalid
structured answers receive no successful score and are not silently dropped.

After **all** model executions stop, the evaluator opens and hash-verifies private
answers. It compares exact malicious event IDs, entity values and ATT&CK IDs.
Precision is matched/reported and recall matched/expected; empty prediction precision
is unavailable. Benign or invented event IDs are false positives. Retrieval metrics
count source-bound record references/explicit event IDs and whole entity values in
signed **raw tool results**, before model-facing guard/truncation; they do not
prove what the model attended to. An observer cap sets `retrieval_complete=false`.

`event_supported_finding_proxy` counts claims tied only to malicious event IDs and
known signed evidence hashes. It is **not semantic finding correctness**. Fill in
`human_correct_findings` and `human_false_positive_findings` after reviewing claims,
citations and acceptable conclusions in the retained cases. Do not publish that
proxy as a forensic-quality score. Proposed findings remain unconfirmed unless the
analyst separately reviews them in the application.

Publish a sanitized, reviewed report with exact model/revision/date, errors,
coverage limitations, run count and method. Keep keys, data-directory paths and
provider diagnostics private. Report repeated runs if comparing nondeterministic
models; one run establishes only its observed result. These synthetic episodes
are small and cannot establish performance on real incidents.
