# Two-hour real-service validation

For the analyst, not an automated quality claim. Exercise the verified pre-release binary under test against a **local Elasticsearch service** and a model you explicitly choose.
Use only the pinned public lab exports below. No dataset is committed to IRMind.
A successful run can supply the missing record for [#63](https://github.com/ns2switch/irmind/issues/63)
and the unobserved H5 steps in [manual validation](manual-validation.md).
Do not mark those checks done before recording their actual results.

## 0–20 min: verified installation and disposable lab

Verify the release, helper, signed checksums and provenance using [platforms](../platforms.md).
Record `irmind --version`, commit, OS and terminal size. Keep this version for the
case. Have Docker Compose v2 and Python 3.11+ available; allocate about 4 GB RAM
and at least 5 GB free disk. The bounded lab uses explicit free-space watermarks
(2 GB low, 1 GB high, 512 MB flood stage); disk protection remains enabled. The lab listens only on `127.0.0.1:9200`, with TLS and no
outbound container network. Never expose this developer service to the internet.

From a checkout matching the release or reviewed launch-preparation commit:

```sh
python3 tools/real-validation/lab.py prepare
docker compose --env-file target/real-validation/compose.env -f tools/real-validation/compose.yml up -d
```

`prepare` asks for a disposable administrator password (16+ characters, hidden).
The image is pinned to Elasticsearch 9.5.6 by an architecture-specific digest.
The certificate service creates a local CA and server certificate with SANs for
`localhost`, `es` and `127.0.0.1`. Its private CA key is discarded after issuing
the server certificate. Do not reuse the lab CA or password elsewhere.
Copy only its **public certificate**:

```sh
docker compose --env-file target/real-validation/compose.env -f tools/real-validation/compose.yml cp es:/usr/share/elasticsearch/config/certs/ca/ca.crt target/real-validation/ca.crt
curl --cacert target/real-validation/ca.crt -u elastic https://localhost:9200
```

curl prompts for the password. Wait for startup if necessary. A request without
the CA must fail trust verification; do not use `-k`. Record both results. A
certificate error is not a reason to disable hostname checks.

Some Docker engines do not publish ports for an `internal: true` bridge. If
`docker compose ... port es 9200` reports no usable mapping and localhost
refuses the connection, keep the internal network and start this optional
development relay in another terminal:

```sh
python3 tools/real-validation/port_forward.py
```

It binds only `127.0.0.1:9200` and forwards opaque bytes through the existing
Compose service to its loopback port. TLS, hostname checks, credentials and
CA verification remain end-to-end. It does not give Elasticsearch outbound
network access. The helper refuses an occupied host port, limits concurrent
connections to eight and each connection to 60 seconds. Stop it with Ctrl+C
when cleaning up the lab. It is a development helper, not part of IRMind.


## 20–40 min: download and load a small, hash-pinned subset

```sh
python3 tools/real-validation/lab.py fetch
python3 tools/real-validation/lab.py load --windows-utc-offset +00:00
```

Confirm the Windows export's intended offset yourself; `+00:00` is an explicit
lab interpretation, not a discovered fact. The helper retains the original text,
source hash, projection identity and confirmed offset in the indexed record.
It loads at most 500 documents into `irmind-validation-events`. A second load
fails rather than replacing existing data silently; reset the lab if necessary.

[datasets.json](../../tools/real-validation/datasets.json) pins:

- Splunk attack_data: one AWS failed-login export and one Windows Security export
  from its controlled attack lab, Apache-2.0.
- EVTX-ATTACK-SAMPLES: a small Windows logon sample, GPL-3.0. Downloaded separately;
  it is not redistributed in IRMind or converted by an unsafe external script.

The downloader handles Git LFS media URLs, checks complete-file SHA-256 and exact
size, and never executes samples. The Python loader creates a narrow **lab ECS
projection**, not a general Splunk converter. AWS explicit login results are
mapped; Windows raw exports retain unknown outcome. For semantic Windows events,
ingest the EVTX original directly in the next step.

Create a four-hour read-only key, writing it **outside the checkout**:

```sh
python3 tools/real-validation/lab.py create-key --key-output ../irmind-lab-key.txt
```

Protect that external file according to your OS permissions. Copy its value into
the IRMind secret form, then remove the working copy. The key has only `read` and
`view_index_metadata` on the single lab index, no cluster or write privileges.
The administrator credential is used only by these development helpers.

## 40–60 min: configure IRMind with full TLS verification

Run `irmind --home <disposable-data-directory>`; complete the file-keystore wizard.
In `/settings connectors`, select Elastic:

| Field | Lab value |
| --- | --- |
| URL | `https://localhost:9200` |
| Source ID | `elastic-lab` |
| Indices | `irmind-validation-events` |
| Account field | `labels.validation_account` |
| Alert space | `default` (alerts are not loaded by this lab) |
| CA PEM | The public `target/real-validation/ca.crt` |
| API key | Enter only in `/settings` → Keystore and credentials. |

Check the displayed CA SHA-256 against `sha256sum` / `shasum -a 256` (PowerShell:
`Get-FileHash`). Save each signed change and unlock again if the configuration requests a restart.
Store the API key in the masked Elastic field of Keystore and credentials, then
enable the connector and review its numbered confirmation. Public CA paths and
activation controls remain scrollable with PgUp/PgDn, even in an 80-column
terminal. If the connector is disabled, storing its public CA need not ask for
an external-data confirmation; enabling it still requires the usual review.
An incorrect CA must fail.
The account selector `lab-evaluation` is an explicit lab label, not an AWS account.
Start with a narrow organization policy as well as a case scope: copy
`policy.toml` into the disposable laboratory directory, retain all limits
and permissions, and set its `[scope]` allowlists to source `elastic-lab`, account
`lab-evaluation` and the observed sample interval. Start with `--policy` pointing
to that explicit policy. Do not add a wildcard or change a denied risk level.

Create a case with `/new`: remote source `elastic-lab`, account `lab-evaluation`,
and a case window covering the dates actually present in the samples. Each
structured connector query must cover **one dataset day at a time**, at most
24 hours. These exports come from different lab exercises and years; do not
claim they form one causally connected attack. Use `/scope` to review it. The organization ceiling must allow only
this source, account and the intended dates; do not widen it to bypass an error.

Ingest `target/real-validation/windows-logons.evtx` locally with `/ingest`.
EVTX must show its verified isolation availability; do not bypass a failed self-test.
Preserve originals until verification/export is complete. The pinned EVTX contains
a zero Windows FILETIME that displays as 1601-01-01, alongside dated 2020 logons.
Retain that raw value as a source-quality caveat; it does not justify extending
the remote search interval to 1601. The AWS exports cover several days in 2022
and the separate Windows text export covers 2021.

## 60–100 min: model, skill, signed plan and approval

In `/settings model`, configure your chosen provider and model. Put its key only
in the SecretBackend form. Review the existing confirmation before sending any
synthetic case data to a remote provider. Test the connection with no case data.
Record exact provider/model/version and, if used, reasoning mode and prices.

For a CPU-only rehearsal, an existing local Ollama installation can use a small
Qwen2.5-1.5B profile. Fetch models explicitly before disconnecting the runtime
from external networking; record its version and model digest. The model's
[documented native output maximum](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct)
is 8,192 tokens. An example runtime Modelfile is:

```text
FROM qwen2.5:1.5b
PARAMETER num_thread 4
PARAMETER num_ctx 16384
PARAMETER num_predict 8192
```

Save it as `Modelfile.lab` and create the local profile explicitly:

```sh
ollama pull qwen2.5:1.5b
ollama create lab-qwen --file Modelfile.lab
ollama show lab-qwen --parameters
```

See [Ollama's Modelfile reference](https://github.com/ollama/ollama/blob/main/docs/modelfile.mdx).
Select that model in the TUI, declare native output 8192 and leave output-parameter
requirement optional. Keep the server on loopback. Four inference threads are a
reproducible laboratory choice, not a universal optimum: excessive CPU threads
can make even the synthetic probe exceed IRMind's unchanged deadline. Size the
runtime for the configured context and simultaneous children; a queued request
may time out on a single-request server. Record such partial outcomes, and do
not increase IRMind's safety deadlines to hide them. A successful probe does not
establish investigation quality; small models can conflate Windows and AWS or
invent conclusions. Check each cited original before confirming any finding.

1. Say `hello`. Record whether it answers naturally without tools.
2. Invoke `/windows-triage Review the local synthetic logons; cite source hashes.`
   Ask separately for a structured Elastic search over one lab day. Record the
   requested query, returned hit count, evidence hash, TLS success and any partial
   coverage. Check that a source/account outside scope is denied.
3. Ask a follow-up that requires the prior answer. Observe streaming and inspect
   a cited original with `/evidence` or the relevant card. Confirm only findings
   actually supported by the collected data. A skill or source alert is not proof.
4. Enable “Confirm all subagent plans” in Preferences. Ask for a bounded plan with
   a Windows child on the EVTX source and a cloud child on acquired AWS evidence.
   First acquire each remote day in the root investigation: child sources are
   frozen, and a child cannot silently inherit a sibling's new evidence. Review
   the plan's sources and allocations before Start; inspect `/subagents`.
5. Cancel one task and check that other completed work remains verifiable. For a
   signed approval exercise, cancel a separate preview plan and then start a new
   one explicitly. This tests Analyst plan approval without introducing another
   service. Do not expect an in-scope SIEM read to require external-enrichment
   approval: the policy distinguishes them. Record any real tool-approval request
   if one occurs; never auto-approve or invent that observation.

A model may not delegate or may not cite the right source. Record that as a
result, not a reason to script the answer or mark the test passed.

## 100–120 min: verify, seal and independent export verification

Run `/verify <source-root>` and `/verify-graph <source-root>` while originals are
available. Uncopied local files are resolved only beneath that explicitly chosen
root. Connector responses retained privately by the case are checked at their
signed case location by size and SHA-256; no second external copy or repeat
service query is needed. A missing or altered retained original fails instead
of falling back to a different file. Review `/report`, proposed findings and pending approvals/tasks.
Only confirmed evidence should support the report. Finish/cancel work before
`/seal`; review the exact hash and key fingerprint, then `/export` with originals
if desired. In a separate clean directory/process, run:

```sh
irmind verify-export <package> --expected-key <independently-saved-analyst-fingerprint>
```

Pin the expected key from the earlier analyst record, not from the package you
are trying to trust. Recheck the export without the data directory or keystore.
Retain private results locally; publish only a sanitized summary with no keys,
personal paths or real evidence. Update the H5 result record only with observed
steps and link the sanitized connector result when closing #63.

Clean up with the same Compose file and environment file, using the `down -v` subcommand.
Delete the disposable key copy, lab password, test case and downloaded data when
no longer needed. Keep any creating executable needed to inspect retained cases.

## Result record (fill in; no pre-filled passes)

| Check | Result / exact observation | Evidence or private record reference |
| --- | --- | --- |
| Date, OS, terminal, IRMind version and commit | Pending | |
| Exact provider, model, revision and reasoning mode | Pending | |
| Dataset pins, hashes, offset and loaded counts | Pending | |
| TLS fails without CA / works with approved CA | Pending | |
| Read-only connector query and signed result hash | Pending | |
| Outside-scope read denied | Pending | |
| Greeting without unnecessary tools | Pending | |
| Investigation answer with correct source-hash citation | Pending | |
| Follow-up retains relevant history | Pending | |
| Streaming response | Pending | |
| Skill receipt and actual coverage | Pending | |
| Plan preview, signed Start and child results | Pending | |
| Cancellation and any tool approval actually observed | Pending | |
| `/verify`, graph reconstruction, seal and pinned-key export check | Pending | |
| Failures, missing coverage and estimated cost | Pending | |

References: [Elastic Docker TLS setup](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-compose),
[API-key creation](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key),
[Splunk attack_data](https://github.com/splunk/attack_data),
[EVTX samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).
