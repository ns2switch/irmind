# Completing SIEM connectors and parallel EVTX decoding

This contract is for contributors implementing the two experimental SIEM modules
and the remaining ingestion concurrency work. Runtime activation stays explicit.
No remote model is enabled by this work.

## Module boundaries and credentials

Each connector has its own crate and Cargo feature, included in the default
binary but disabled until configured. Both implement the existing async,
cancelable `SiemPort::execute(AuthorizedCall, CancellationToken)` entry point.
They cannot create an authorized call. A selected source, case scope and the
organization ceiling continue to constrain every request.

| Module | Explicit secret field | Non-secret settings |
| --- | --- | --- |
| `siem-elastic` | `IRMIND_ELASTIC_API_KEY` | HTTPS origin, source ID, approved index patterns, alert space, account field, optional CA path and digest |
| `siem-chronicle` | `IRMIND_CHRONICLE_SERVICE_ACCOUNT_JSON` | Regional HTTPS origin, project, location, instance, source ID, account field, optional CA path and digest |

Secrets come from `SecretBackend` at composition time. No connector reads ambient
credentials, application-default credentials, environment variables or key files.
Settings display the configuration requirements without credential values. CA
files use the existing complete TLS and hostname verification path.

Elastic needs no new third-party production package. It reuses reqwest,
serde_json, secrecy and the existing HTTP safeguards. The Chronicle proposal adds
`ring = 0.17.14` as a direct dependency for RS256 service-account assertions;
that exact package already exists in the main lockfile. This avoids introducing
a separate JWT parser and algorithm-selection layer. Base64, serde_json and
zeroize are already present. Only RS256 is accepted; the token URL and OAuth
scope are fixed by the module, never by downloaded JSON or a model argument.

The private key, assertion, access token and token response are redacted in Debug
and errors. Assertions expire after a short bounded interval. Tokens live only
in memory and requests do not log URLs or bodies. OAuth and data HTTP clients
both disable redirects, have timeouts, enforce body limits and support cancellation.

## Elastic API and structured searches

Use [Elasticsearch Search API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search):
`POST /<configured-index-patterns>/_search`. The module generates Query DSL from
C6's closed fields, operators, aggregations, time bounds and result count. It
never accepts a model-supplied query, script, index name, runtime mapping, SQL,
Lucene expression, KQL or ES|QL. Values become JSON strings, not query fragments.

The request always includes the authorized account and UTC window in bool
filters, independent of model values. The configured index allowlist is encoded
into the endpoint, and cross-cluster selectors and arbitrary endpoint paths are
rejected. Term aggregations and event results retain the current bounded limits.
A timed-out or partial shard response is explicitly marked, not reported complete.

Alert lookup queries the configured exact
[Security alert alias](https://www.elastic.co/docs/solutions/security/detect-and-alert/query-alert-indices),
`.alerts-security.alerts-<space-id>`, with the same account and time filters plus
an exact alert ID. It uses documented
[alert fields](https://www.elastic.co/docs/reference/security/fields-and-object-schemas/alert-schema)
rather than assuming `_source` contains every field. No alias wildcards span
other spaces. Minimum API key privileges are `read` on the selected data indices
and alert alias, without cluster-management or write privileges.

Returned ECS fields remain original source data in `SourceRecordV1`. An identified
mapping supplies common-event interpretation. Neither the transport module nor
a parser infers a role, outcome or category from arbitrary text.

## Chronicle API and structured searches

Use the documented
[Chronicle v1alpha UDM search](https://docs.cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances/udmSearch):
`GET /v1alpha/projects/<project>/locations/<location>/instances/<instance>:udmSearch`.
The body is empty. The module fixes the resource and emits encoded `query`,
`timeRange.startTime`, `timeRange.endTime`, `limit` and `queryDialect=YL2` parameters.
It builds the boolean UDM expression from closed structured operations; values
are escaped literals. Account and time constraints cannot be replaced by model
text. A configured account field must be a bounded validated UDM field path;
an unsupported deployment field produces a clear provider error, never a retry
without the account predicate. Continuation and truncation remain explicit.

The minimum search IAM permission is `chronicle.events.udmSearch`, on the
configured instance. The service account obtains an OAuth token through the
fixed Google token endpoint with the documented Chronicle scope. No write,
rule-management or response-action permission is requested.

The current API also documents
[case detection lookup](https://docs.cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.cases.detections/get)
and [bounded detection listing](https://docs.cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.legacy/legacySearchDetections).
These are distinct from UDM events. The first has no server-side account/window
predicate; the latter has a server window but no general UDM account predicate.
The implementation must not substitute a UDM event and call it an alert, or
request a broader detection listing and silently filter it locally. Alert
retrieval needs a documented endpoint that enforces the required namespace,
account and window, or an explicit narrower configuration contract before it is
enabled. Unsupported alert operations fail clearly before transferring data.

### Explicit namespace scope for detection reads

A configuration can declare `scope_mode = "instance"` instead of the default
`scope_mode = "event-account"`. In instance mode, `account` in the existing SIEM
scope means the configured Google Cloud project hosting the SecOps instance.
The connector requires an exact match and fixes the full instance resource in
every endpoint. This is a tenant-wide source, not a claim to filter AWS, Azure
or GCP event accounts within that tenant. The settings confirmation explicitly
states that all event accounts in that instance are in scope; the organization
ceiling and case must both authorize the hosting project and source.

Only instance mode enables detection reads. `siem_get_alert` retrieves the exact
requested detection ID from `legacySearchDetections`, with a configured rule ID,
server-enforced start/end time, bounded page/result/body counts, and a truncation
marker if the bounded scan cannot find the requested ID. It never reports a
missing detection when the scan was partial. IAM additionally requires
`chronicle.legacies.legacySearchDetections`. Event-account mode still forces its
UDM account predicate for searches and refuses detection reads before HTTP;
it never changes scope mode or removes a predicate automatically.

No new policy port or signed format is needed: instance mode uses a declared
source and the existing explicit account identifier. Switching modes is an
audited, analyst-confirmed egress configuration change. Tests cover wrong
hosting project, another instance/resource, missing window, event-account alert
rejection, exact detection selection and bounded partial results.

UDM search records are decoded to `SourceRecordV1` with original field types and
explicit provenance. A separate mapping owns the UDM-to-common-event mapping.
No borrowed ECS compatibility projection invents UDM field meaning.

### Case-local scope record and analyst-only configuration

Scope mode is an analyst configuration field, not a tool argument. No model tool
can select it or write connector settings. Installing or changing the mode uses
the signed global configuration operation and explicit egress confirmation;
instance mode explains that it includes every event account in that instance.

The release registry carries the effective SIEM source descriptors into the
engine without extending `SiemPort`. On opening an unsealed case and before a
remote execution, record relevant source modes in versioned `ModulesActivated`
details, sorted by source ID and bound to the configured instance/project and
case scope. Existing fingerprint-only `ModulesActivated` payloads keep their
bytes. The signed-entry envelope, seal and export encodings do not change.
Package exports include the case chain and therefore these scope details.

The case view permanently shows a full-instance warning when its signed source
records include instance mode. The warning survives scrolling, inactive
connectors and reopening; the scope detail lists the exact source and namespace.
Sealed cases retain their recorded modes without appending new case entries.
Tests cover an obedient fake model attempting a mode change, a persistent TUI
warning, organization-ceiling denial and exported signed scope details.

## EVTX: bounded chunk decoding inside the existing helper

The existing `SourceDecoder::decode_with_budget` contract already supplies the
worker budget. Keep its public signature. Pass a validated bounded worker count
to the fixed helper command, without a shell or environment configuration.

Use standard-library worker threads over owned EVTX chunks. The coordinator
reads chunks in file order; workers decode independently; bounded channels
return records in chunk/record order to the existing canonical NDJSON writer.
Keep measured physical offsets, checksum validation, record/byte/time limits,
parent cancellation supervision and whole-file rollback. No Rayon feature or
new production dependency is needed for this implementation.

The coordinator alone enforces total records and total output size. Every worker
has a bounded queue and at most one decoded chunk in flight. An abort flag and
channel disconnection stop all producers on consumer failure. Joining workers
must not block cancellation indefinitely; the supervising process deadline still
terminates the entire isolated process tree.

### Linux thread-only sandbox extension

Linux currently denies thread creation along with process creation. To run the
same bounded decoder there, extend seccomp only for pthread lifecycle operations:
allow `clone` only with the closed thread-sharing flag combination (including
VM, SIGHAND and THREAD, without namespace or process flags), permit the required
thread-local registration operations, and return ENOSYS for `clone3` so libc uses
the inspectable `clone` form. Reject every other flag set. No socket, exec,
filesystem-open or process-fork permission is added. Landlock is installed before
workers start and is inherited by every thread; seccomp is also inherited.

Keep the same safe Rust boundary and unsafe restrictions. macOS and Windows
retain their existing containment. Windows source scheduling stays serial and
reuses the single verified session witness. Threads inherit the AppContainer
and the job's process-tree lifetime constraints.

Native tests must prove thread creation works, fork/exec and all existing
network/filesystem probes remain denied, invalid clone flag sets are denied,
and helper bytes match at 1, 2, 4 and the full budget. Benchmark the same release
build and synthetic EVTX corpus at 1, 4 and all available cores on each platform.
A platform only exposes the concurrent helper after its native tests pass.

## Remaining multicore measurements

Before another change to writing, profile one and four workers in the same job:
read/hash, decoder, mapper, canonical row append, compression/finalization,
signed custody and queue waits. Report wall time, CPU time, allocation counts and
peak RSS; do not add non-overlapping wall durations for parallel phases.

Keep canonical row admission and deterministic partition eviction in one order.
Evaluate parallel encoding/compression of independent deterministic row groups
or partition writers, with a global memory budget and bounded work queues. The
existing parallel writer close remains enabled. Any physical-byte change needs
its own identified builder and review; current-format goldens stay fixed.

Measurements include paired 1 GiB sources, one 4 GiB NDJSON source and one 1 GiB
EVTX source, followed by the complete nine-scenario 15 GB release matrix. The
absolute release gates, cancellation, rollback, provenance, policy ceilings,
query sampling/expansion limits and ordinary query deadlines do not change.
