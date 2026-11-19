# Log parsers

This page helps analysts choose a local log parser and test a custom format before ingestion. All current parsers are experimental and have synthetic test coverage. An analyst has also reported a [partial investigation with a real model and locally ingested public CloudTrail data](development/manual-validation.md#partial-real-model-investigation-2026-11-17); this does not validate every parser, a remote connector or real-incident use. See [modules](modules.md) for individual formats and [configuration](configuration.md) for the data directory.

## How a parser is selected

The registry passes at most the first 64 KiB to every compiled detector. A filename is a hint, never proof. One unique match at 80% confidence or higher selects the parser automatically. Low-confidence matches and ties require analyst confirmation. Unattended ingestion does not choose an ambiguous parser. The selected identity, version, confidence and selection mode enter the signed source manifest.

`/ingest` opens the file picker. Use `/ingest --parser <name> <path>` for an explicit choice; it is audited. In **Settings → Preferences**, inspect compiled parser names and versions. Compilation includes no automatic remote model selection.

| Parser | Input | Detection | Mapped fields | Status |
| --- | --- | --- | --- | --- |
| Microsoft 365 Unified Audit Log | Purview CSV, Search-UnifiedAuditLog JSON, Management Activity API JSON | Native AuditData/Operation, CreationTime and workload; 98 | UTC time, actor, mailbox target when explicit, resource, source IP, user agent, workload, finite operation/outcome tables | experimental |
| Okta System Log | API JSON arrays and JSON/NDJSON exports | eventType, uuid, actor and published time; 98 | Authentication, MFA, administration, policies and impersonation; actor/target and source IP | experimental |
| Route 53 VPC Resolver | JSON, NDJSON | Version 1.x, query, client and VPC or profile, 98 | DNS question, type, class, client, port, response code, account and Region | experimental |
| GitHub audit log | Organization and enterprise CSV and JSON, native streamed NDJSON | Native action, time and audit identity/scope, 98 | Membership, tokens, keys, repository access and Actions configuration | experimental |
| Google Workspace Reports API | JSON pages, arrays, objects and NDJSON | Native activity ID, application, time and events, 98 | Login, SAML, administration, OAuth, Drive and Gmail with original fields | experimental |
| macOS Unified Log and eslogger | JSON arrays, objects and NDJSON | Native Unified Log fields or Endpoint Security envelope and schema, 98 | Process, file, authentication, session, mounts and selected security notifications | experimental |
| CrowdStrike FDR | JSONL, plain or gzip | Native event_simpleName, cid, aid and timestamp; 98 | Process IDs separated by tenant/sensor, record-scoped PIDs, endpoint roles, DNS/authentication and finite file/registry rules | experimental |
| Microsoft Defender | Advanced Hunting CSV/JSON and Streaming JSON | Native Timestamp, DeviceId/ActionType or AlertId, plus source layout: 98 | Process/parent, file, registry, network and logon; AlertInfo/AlertEvidence remain unconfirmed | experimental |
| RFC 5322 email | One `.eml` or header dump per file; bounded MIME parts | From plus native header combination: 98; minimal headers: 70, analyst choice | Ordered Received hops, addresses, raw headers/body bytes, literal URLs and attachment metadata/hashes; email outcome stays unknown | experimental |
| AWS GuardDuty | API, CLI/console and EventBridge JSON | Native account, finding ID/type, region, resource and time; 98 | Unconfirmed source alert, actor/resource/IP roles, exact severity and original observation times | experimental |
| AWS VPC Flow Logs | Headered/custom and standard v2 text, gzip, CloudWatch messages | Native column header: 98; headerless v2: 70 and analyst confirmation | Network endpoints/roles, explicit disposition, bytes/packets, account/region and explicit instance host | experimental |
| Azure flow logs | VNet and NSG JSON containers | Provider category and native flow structure: 98 | Original tuple, precise native epoch, endpoints, explicit disposition, counters, subscription and rule | experimental |
| GCP VPC Flow Logs | Cloud Logging JSON/NDJSON and entries envelopes | VPC flow logName, connection fields and timestamp: 98 | Endpoint roles, project, observer VM, bytes/packets; missing disposition remains unknown | experimental |
| Windows EVTX | Binary EVTX: Security, System, PowerShell, Sysmon | Valid EVTX header and checksum; 95 | UTC time at 100 ns precision, host, user, process, IP/port and real record offsets | available; experimental |
| Linux | auth.log/secure, auditd, journald JSON, HTTP common/combined | Authentication tags, audit headers, journal fields or HTTP header; 95 | UTC time, host, user, process, command, IP/port, action/result; bounded audit correlation | experimental |
| Syslog | RFC 5424 / RFC 3164, plain or gzip | PRI and timestamp/header shape; 95 / 90 | UTC time, host, application, PID, facility, severity, message and raw data | experimental |
| GCP Cloud Audit Logs | JSON/NDJSON LogEntry; GKE audit exports | Original protoPayload method/service and timestamp | UTC nanoseconds, explicit status, principal/resource/endpoint roles; confirmed GKE cluster | experimental |
| Microsoft Entra ID | Azure Monitor JSON/NDJSON and Log Analytics object rows | Documented category or Type and original time | Sign-ins and audit, explicit outcome, tenant, actor, target and IP | experimental |
| JSON and exported cloud logs | JSON/NDJSON; AWS, GCP, Azure and HuntEval | Recognized record fields | Time, identities, accounts, resources and IPs | experimental |
| ECS | NDJSON | ECS version and timestamp/characteristic fields | Event, host, user, source, destination, process, file, URL | experimental |
| OCSF | JSON/NDJSON or local Parquet | Class, category and schema metadata; Parquet needs confirmation | Authentication, API, network, process, file and findings | experimental |
| DFIR tools | Velociraptor, Hayabusa, Chainsaw, plaso, EZTools | Format markers or exact CSV headers | Time, host, user, process, action and available entities | experimental |
| Zeek | TSV headers or JSON for conn, dns, http, ssl, files, x509, notice and weird | Bounded header/field match; 95 for conn/DNS fixtures | Precise time, source/destination endpoints, UID correlation, explicit sensor host | experimental |
| Suricata EVE | alert, flow, dns, http, tls, fileinfo and anomaly JSONL | Supported event type, timestamp and flow ID; 95 | Precise time, flow correlation, endpoints, unconfirmed detections and explicit host | experimental |
| Kubernetes audit | Native `audit.k8s.io/v1` Event JSON/NDJSON | Explicit API version and kind; 98 | Original fields and nanosecond timestamps; signed cluster context. Semantic classification is provided separately by mapping modules. | experimental |
| Falco | JSON/NDJSON detections | Rule, priority, timestamp and output-fields object; 98 | Original rule/output fields and precise time; Kubernetes records require confirmed cluster context. Source detections are not analyst confirmations. | experimental |
| Declarative | CSV, JSON, NDJSON or bounded regex | Exact header, required JSON pointers or sample regex; at most 70% | Explicit mapping described below | experimental |

## Cluster acquisition context

Native Kubernetes audit events do not contain a globally unique cluster identity. Before ingestion, the TUI asks for an explicit provider-qualified identity, such as `kubernetes:urn:k8s:team-a`. Confirm it for one file or explicitly select the batch option. There is no default from the machine, file name or directory. Falco requires the same confirmation when Kubernetes metadata is present; host-only detections do not invent a cluster.

The automation equivalent is `irmind ingest <case-id> <path> --cluster kubernetes:urn:k8s:team-a`; the conversational input accepts `/ingest --cluster kubernetes:urn:k8s:team-a <path>`. Both use the same bounded typed context in the signed source manifest and reconstruction. A source without required context fails closed; confirming an identity never grants a remote permission. Equal names in different clusters or namespaces remain distinct. Native decoders retain request/response bodies as original source fields, rather than automatically placing them in the searchable projection.

These modules cover native Events, EKS CloudWatch GetLogEvents envelopes and AKS kube-audit/kube-audit-admin diagnostic exports. GKE Cloud Audit exports use the GCP module below. No live Kubernetes API connector is enabled.

## Current readers and existing cases

New ingestion uses the current parser version recorded in its signed source manifest. JSON uses `json-source-v1`. Historical parsing engines are not retained. Existing signed bytes can still be authenticated and exported; to regenerate records from an older reader, create a new case and ingest the verified originals. Reinstall declarative definitions after a reader-version update. See the [changelog](../CHANGELOG.md#known-issue-fixed).

## Windows coverage

Use processed exports to investigate these artifacts today. All listed modules are experimental and tested with synthetic data. IRMind ingests the exports; it does not run KAPE, EZTools, Velociraptor or plaso, or open their raw binary artifacts itself.

| Artifact | What it helps answer | Current ingestion route |
| --- | --- | --- |
| Windows event logs, including Sysmon | Which logons, process or service events were recorded, and how do they correlate? | Hayabusa CSV/JSONL → `parser-hayabusa`; EvtxECmd CSV → `parser-eztools`. Direct `.evtx` → `parser-evtx` with the isolated helper; Hayabusa and EvtxECmd exports remain alternatives. |
| Registry hives and related transaction logs | Which account, configuration or persistence-related keys and values were reported? | Process externally with RECmd batch; ingest its CSV with `parser-eztools`. |
| Prefetch (`.pf`) | Which executables, run counts and reported run times appear? | PECmd CSV → `parser-eztools`. |
| Amcache | Which application paths, hashes and inventory timestamps were recorded? | AmcacheParser CSV → `parser-eztools`. |
| AppCompatCache / ShimCache | Which paths and cache metadata were recorded? | AppCompatCacheParser CSV → `parser-eztools`. Cache presence alone is not an execution verdict. |
| `$MFT` | Which file paths and filesystem timestamps were reported? | MFTECmd CSV → `parser-eztools`. |
| LNK shortcuts | Which targets, working directories and shortcut timestamps were reported? | LECmd CSV → `parser-eztools`. |
| SRUM (`SRUDB.dat`) | Which applications and users have recorded resource or network-usage data? | SrumECmd CSV → `parser-eztools`. Usage totals alone do not establish exfiltration. |

For these artifacts, another supported route is a timestamped Velociraptor JSONL artifact result through `parser-velociraptor`, or a plaso `psort` `json_line` export through `parser-plaso`. Export schemas must match the [module contracts](modules.md#velociraptor-parser): arbitrary collector output is not automatically supported. EZTools detection requires the exact recognized column names and a usable timestamp; unmapped fields remain in the record. Start with event timelines, then correlate execution, persistence, lateral movement and possible exfiltration rather than treating one artifact as proof.

[KAPE targets and modules](https://github.com/EricZimmerman/KapeFiles), [EZTools](https://ericzimmerman.github.io/) and [Velociraptor artifacts](https://docs.velociraptor.app/docs/artifacts/) describe collection and external processing. Keep originals and select the processed export files for ingestion. Native registry and `$MFT` parsing remain demand-driven future work under the isolated-helper model used in the [roadmap](development/roadmap.md#delivered-through-v05x). [A Volatility 3 JSON parser](https://github.com/ns2switch/irmind/issues/158) is planned; direct memory-image parsing is not available.

## A custom format without Rust

Open `/parsers`. Choose **Test definition** and enter a TOML file and a small sample file. The preview shows detection confidence and at most ten guarded rows. It does not ingest evidence, create a case or contact a model. `/parsers test <definition> <file>` opens the same form with paths filled in; use the form for paths containing spaces.

Start from one of the [examples](examples/parsers/README.md). A definition contains:

- `version = 1`, a lowercase name and a short description.
- `input.format`: `csv`, `json`, `ndjson` or `regex`. CSV declares its delimiter and header. Regex uses named captures and the linear-time Rust regex engine.
- `detect.header`, `detect.required_fields` or `detect.pattern`. Detection confidence is 1–70, below native high-confidence formats. For JSON, required fields are JSON pointers. The detector checks only the bounded sample.
- `mapping`: common output field to CSV column, JSON pointer or regex capture. `time` is mandatory. Optional fields are `host`, `user`, `process`, `command_line`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `action`, `outcome`, `account` and `region`. Other original data stays in the record.
- `timestamp.format`: `rfc3339`, `unix` in decimal seconds, or a chrono date/time pattern. `timestamp.default_timezone` is `UTC`, `Z` or an explicit fixed offset such as `+02:00`. A source offset takes precedence. Full source timestamp text is retained; current artifacts preserve reported precision using UTC microseconds and a nanosecond remainder.
- Optional stricter `limits`: `record_bytes`, `depth`, `fields` and `records`. Definitions cannot raise the hard limits: 1 MiB per record, depth 32, 1,024 JSON fields and 10 million records. Each source is capped at 50 GiB.

Definitions are at most 64 KiB. Regex source is at most 4 KiB, with a 1 MiB compiled/DFA bound per regex. Preview input is at most 1 MiB. Malformed records are counted with at most three escaped, bounded excerpts; an unrecoverable framing or file-limit error stops that file. No input is executed.

## Install, change, deactivate and recover

Review the preview first. Choose **Install definition**, inspect its name and SHA-256, and confirm **Sign and apply**. The application signs the complete validated definition in its global operational chain, writes it atomically with private permissions, and restarts the session. No case is required. Install a revised file through the same flow; never edit active files to bypass approval.

Accepted files live in `parsers/active/` under the private data directory, with content-addressed copies in `parsers/archive/`. A missing, edited, invalid or unsigned file stays disabled and is visible in `/parsers`; it does not prevent startup. **Restore approved file** explicitly restores the signed snapshot. **Deactivate definition** signs the removal from future detection; historical signed versions remain available for reconstruction. Installation failure after signing leaves an unavailable definition, requiring explicit restoration, never silent acceptance.

The definition hash is part of the parser version in the existing source manifest. Rebuilding an old case resolves that exact signed version, even after replacement or deactivation. Exported manifests retain the pinned hash; reconstructing on another machine also requires the matching approved definition. Export verification itself does not execute definitions. Symlink definitions are rejected. Temporary writes stay within the private data directory and are removed after completion or error; startup cleans orphaned definition temporaries.

All mapped records retain taint and source/parser/offset provenance. The guard screens preview, evidence shown on screen and model context. A definition cannot grant a tool permission or alter organization policy. Keep expected answers from synthetic evaluation episodes outside the source directory you ingest.

### Legacy syslog time

RFC 3164 opens a time-context form before ingestion. Confirm the first record’s year and fixed UTC offset, whether December → January advances the year, and whether to apply the choice to one file or the whole ingestion. Fields start empty. Verified sources from the same host may suggest a year and offset; you must confirm them. IRMind never uses the machine clock or file modification time. Other backward month transitions count as invalid records. The choice is signed with the source. See the [syslog contract and limits](development/syslog-parser.md).

### Linux exports

Classic auth.log/secure uses the same per-ingestion time form as syslog. Journald keeps the original microsecond timestamp. Auditd groups bounded records with the same node, timestamp and serial; unfinished groups stay marked partial. Standard HTTP access formats provide no server-host field, so IRMind leaves it unknown. For custom log formats, adapt the [declarative HTTP export example](examples/parsers/nginx-apache-custom.toml). The [Linux contract](development/linux-parser.md) lists limits and mapping details.

### Windows EVTX

Each EVTX source is limited to 4 GiB and 8,000,000 records. The helper has a 600-second invocation deadline, a 4 MiB frame limit and a total output budget of at most 8 GiB (also bounded by 32 times source bytes plus 1 MiB). Reaching a limit rejects the complete file with an explicit diagnostic; no partial source is published. Windows parses sources in canonical order while their initial hashes remain parallel.

EVTX is available in source builds and signed release packages from v0.2.0. The v0.1.x packages do not include its helper. The experimental `parser-evtx` module uses the separately installed `irmind-evtx` helper. It recognizes the EVTX header and checksum, not the file extension. The helper receives one read-only file handle; it cannot open the evidence by path. Both local files and downloaded, case-private object spools use that route.

Linux requires kernel 5.13 or newer, Landlock ABI 1 enabled, and unprivileged seccomp. No Bubblewrap installation is required. Windows requires the BFE and MpsSvc firewall services to remain active. It uses a capability-free AppContainer, an explicit standard-handle list and a kill-on-close Job Object. macOS uses a deny-default sandbox profile. A startup probe verifies denied foreign reads, denied networking and denied child creation. If the probe fails, Preferences reports why EVTX is unavailable; there is no unconfined mode.

Security, System, PowerShell and Sysmon events map to the common schema. Unmapped fields remain in the record. The original FILETIME timestamp retains its 100 ns resolution, and provenance records the actual file offset and record number. The [helper design](development/evtx-helper-design.md) documents limits, mappings and the platform test requirements. Use the matching helper from the same verified release beside the main executable.

Tested native environments: Ubuntu 22.04 and 24.04, Debian 12 (kernel 6.1), macOS 26.6.2 arm64 and Windows Server 2025. Fedora 44 was tested as container userspace only. Windows 10/11 clients remain experimental and unconfirmed; see the [Windows 11 validation issue](https://github.com/ns2switch/irmind/issues/189) and the [exact platform evidence](development/evtx-helper-validation.md). Runtime isolation checks must pass on each installation.

For a source build, build the main executable normally, set `CARGO_TARGET_DIR` to `target` in your shell and run `cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked` from the repository root. Use the same target directory for both workspace builds. Keep `irmind-evtx` (or `irmind-evtx.exe`) beside the main executable. The automatic native self-test decides availability; installing a helper never bypasses it.

### Network exports

Zeek and Suricata are experimental modules compiled by default. Current V3 ingestion preserves subsecond time and uses the endpoint-host partition profile. Zeek's explicit `sensor_host` supplies the collector host; its HTTP `host` remains a domain. A missing sensor host is never inferred from an IP or filename. Correlation IDs are source observations, not confirmed attack paths. See [Zeek](modules.md#zeek-parser) and [Suricata](modules.md#suricata-eve-parser) for supported records and limits. Both readers count oversized lines, retain bounded rejected samples and continue with subsequent well-framed records.

### Kubernetes and Falco interpretation

Bundled `mapping-kubernetes` tables classify audit API results from explicit HTTP
status codes; an absent status stays unknown. Actor and impersonated user are
distinct. Target pod, node, namespace and service-account observations require
an explicit resource type; service accounts retain their own namespace even
when accessing another namespace. The complete source IP array stays original;
the first reported address is indexed as a source claim.

`mapping-falco` has separate host and Kubernetes selectors. Falco rules are
source alerts, not analyst-confirmed findings. Container OS users remain
source-record-scoped users, rather than Kubernetes API principals. Process IDs
never imply a process lifetime. Container IDs and image repositories are
queryable within confirmed cluster scope; image tags and pod request bodies
remain original evidence. No fields from full Kubernetes request/response
bodies are automatically projected into search.


The additional `mapping-falco-kubernetes-audit` table handles Falco's explicit `source="k8s_audit"` format and documented `ka.*` fields. It keeps API actors and impersonated targets separate, retains the audit ID, and requires confirmed cluster context even when no syscall `k8s.*` metadata exists. An alert remains unconfirmed with unknown outcome; its response code is a source observation, not proof of a successful attack. An explicit boolean `container.privileged` is mapped for runtime observations; it is never inferred from a rule title. Kubernetes 1xx protocol-upgrade responses remain unknown rather than successful execution.

Whole pod/RBAC bodies stay out of the index. The [Kubernetes methods](skills.md) use the explicit verified-original view for the necessary source facts, under the existing guard and local-query limits.

### GCP Cloud Audit Logs and GKE

The default experimental `parser-gcp-audit` module recognizes original Cloud
Audit LogEntry JSON or NDJSON. `mapping-gcp-audit` interprets exact documented
service/status values; `mapping-gke-audit` additionally validates GKE resource
paths. Missing status stays unknown. Provider-redacted addresses are not IP
entities. Generic JSON remains a low-confidence fallback for these exports.

For GKE, confirm the complete source identity
`gke:projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER`. The form shows
source-label suggestions; neither the first suggestion nor a batch default is
accepted silently. Unseen later clusters require additional confirmation;
contradictory manual context is rejected. Split exports with more than eight
clusters, or containing both GKE cluster and non-cluster resource types.

Export examples, with read-only logging access configured outside IRMind:

```sh
gcloud logging read 'logName:"cloudaudit.googleapis.com" AND NOT resource.type="k8s_cluster"' --project=PROJECT_ID --format=json > cloud-audit.json
gcloud logging read 'resource.type="k8s_cluster" AND protoPayload.serviceName="k8s.io"' --project=PROJECT_ID --format=json > gke-audit.json
```

Choose the project and UTC window permitted by the case and use the provider's
export controls to bound the collection. Exporting does not grant IRMind any
cloud credentials. See [Google's audit format](https://cloud.google.com/logging/docs/audit/understanding-audit-logs)
and [GKE export filters](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging).

### Microsoft Entra ID

The default experimental `parser-entra` recognizes Azure Monitor resource logs
with `category` and `properties`, including a `records` envelope, and Log
Analytics object rows with `Type`. It covers interactive, non-interactive,
service-principal and managed-identity sign-ins, and AuditLogs. Nanosecond time,
field names/types, offsets, MFA and Conditional Access details remain original.
Graph `value` wrappers and positional `tables/columns/rows` query responses need
an explicit conversion; they are not this source format.
The [mapping](mappings.md#microsoft-entra-id) keeps actor and target separate.

### Managed Kubernetes exports

EKS: enable control-plane audit logging and export the relevant CloudWatch audit
stream using GetLogEvents. `parser-kubernetes` recognizes `events[].message`
and NDJSON object rows with `timestamp` and `message`. Confirm the full ARN as
`eks:arn:aws:eks:REGION:ACCOUNT:cluster/NAME`; a stream or filename alone does
not establish cluster identity. The original transport row and decoded Event
remain together, with the actual outer-row offset. Subscription base64/gzip
payloads are not automatically decoded.

AKS: configure a Storage diagnostic export for kube-audit and/or kube-audit-admin,
then download its `records` JSON. `properties.log` and AzureDiagnostics object
rows with `Category`, `ResourceId` and `log_s` are supported. The complete
resourceId is a suggestion requiring confirmation; conflicting IDs are rejected
and a newly encountered cluster requests confirmation again. A positional
AKSAudit query row is not turned into an invented Event. Export only authorized
streams/windows and confirm identities per source.

GKE: use the Cloud Audit LogEntry export above; both NDJSON and gcloud JSON
arrays are detected. Retain the complete cluster labels. For a self-managed
cluster, configure the API server audit log backend and collect its JSON/NDJSON
Events through an authorized read-only path. See the
[formats and primary references](development/managed-kubernetes-transports.md).

## Microsoft 365 and Okta exports

Export a Purview audit search as UTF-8 CSV retaining the `AuditData` column, or
export `Search-UnifiedAuditLog` results as JSON retaining that field. Management
Activity API JSON records can be ingested directly. Preserve the original files;
IRMind neither executes PowerShell nor requests tenant access. The decoder extracts
the native audit object, retaining operation parameters as untrusted searchable
fields. Mailbox targets use `MailboxOwnerUPN` when supplied; an object path is not
assumed to be a user. The documented UTC `CreationTime` is retained precisely.

Export Okta System Log API responses as JSON arrays or one original event per line.
Keep `published`, `uuid`, `eventType`, `actor`, `target`, `client`,
`authenticationContext`, `securityContext` and bounded `debugContext` intact.
The mapper uses documented event names and explicit outcome values; missing or
unrecognized outcomes remain unknown. Unknown operations remain searchable API
records. Neither module uses a remote connector or requires credentials.

Original arrays remain searchable. The scalar common schema projects the first
user target; additional distinct targets remain in the original with a coverage
diagnostic. A missing tenant is never inferred from an ISP or file name: Okta
user observations retain source-record scope. M365 uses an explicit OrganizationId
when available. None of these mappings uses process-lifetime scope.

Sources: [Microsoft audit schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema),
[Purview export](https://learn.microsoft.com/en-us/purview/audit-log-export-records),
[Okta System Log](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog),
[Okta event catalog](https://developer.okta.com/docs/reference/api/event-types/).

## GuardDuty exports

Ingest the JSON from GetFindings, the AWS CLI `get-findings` output, a console
finding export or an EventBridge GuardDuty event. The module recognizes the
lower-camel-case wire format and the SDK/CLI's PascalCase format separately;
it does not rewrite their original keys. Source-specific outer-array framing
streams `findings`/`Findings` without consuming the first line as a sample.

All finding types, including unknown ones, remain unconfirmed source alerts.
Severity retains its exact decimal representation. Creation/update and
first/last-observed fields remain in the original. API-call remote IPs have the
source role; network-connection endpoints require the explicit connection
direction. Unknown directions do not invent an endpoint role. Resource-specific
fields not in the common schema remain searchable. No GuardDuty API connection
or credential is created by local ingestion.

Sources: [GetFindings wire schema](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html),
[CLI output](https://docs.aws.amazon.com/cli/latest/reference/guardduty/get-findings.html),
[finding details](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html).

## Cloud network flow exports

Export AWS VPC Flow Logs from S3 as plain text or gzip, retaining the configured
column header for custom formats. CloudWatch `events`/`logEvents` message exports
are also supported. A headerless file requires an explicit analyst selection of
`parser-vpc-flow`, confirming the standard 14-field version 2 layout. The TUI
shows this requirement in the parser selection panel; unattended detection does
not ingest it automatically. Use a header for any custom layout. Unknown columns
remain in the original decoded record. Only an explicit `instance-id` supplies a
host partition; an interface ID is not assumed to identify a host.

Export Azure VNet or NSG flow-log JSON from the configured storage account without
rewriting its nested `flows` and `flowTuples`. VNet tuple timestamps are epoch
milliseconds; NSG tuple timestamps are epoch seconds. Versions 2/4/5 of VNet and
1/2 of NSG are recognized. An unknown version is retained once as an unclassified
network record without applying a known tuple layout. Expanded tuples do not
invent byte offsets within an escaped JSON string. Rule, resource and original
tuple fields remain searchable. A MAC address does not become a host identity.

Export GCP Cloud Logging entries retaining `logName`, `timestamp`, `resource` and
`jsonPayload.connection`; the source log must identify `vpc_flows`. Preserve the
native `src_instance`, `dest_instance` and `reporter` fields for host attribution.
An explicit `DROPPED` disposition maps to failure. The absence of this field does
not prove acceptance. GCP sampled/estimated payload-byte counters, Azure delta
counters and AWS flow counters retain their provider semantics; they are not
interchangeable billing or packet-capture measurements.

All three families use separate decoders and mapping modules. Finite outcome
and field tables are included declaratively; native glue validates different
numeric representations and expands bounded Azure tuples. These are local
exports, not live connectors. Record/source limits, taint, source hashes and
signed parser/mapping provenance apply. Compact or gzip inputs can exceed the
normalized-size allowance even below the source-size limit. VPC uses a bounded
32× decoded-byte allowance, with a read-only gzip counting preflight and full
group/sort disk reservation. Other modules retain their existing allowance. A
quota overrun rejects the source/group rather than silently dropping records.

Sources: [AWS flow record fields](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html),
[Azure VNet flow format](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview),
[Azure NSG flow format](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview),
[GCP flow records](https://docs.cloud.google.com/vpc/docs/about-flow-logs-records).

## Email exports

Save the original message as `.eml` from the mail client, including full headers
and MIME structure; use one message per file or select a directory. A header-only
dump is also supported. IRMind does not connect to a mailbox, follow links, open
attachments or unpack archives. Keep the originals: hashing in place does not
implicitly copy them into the case.

The decoder retains raw header order and exact header bytes, including Received
hops, From, To/Cc, Reply-To, Return-Path, Message-ID, Date, Authentication-Results,
X-Originating-IP and provider headers. Structured mailbox and MIME parameter
parsing uses the bounded headers-only library entry point. IRMind owns MIME
traversal. Plain text and literal HTML source are retained in bounded chunks;
HTML is never rendered. Base64 and quoted-printable transport encoding are decoded
once. HTTP(S) URLs are literal values: URL escapes and HTML entities are not
repeatedly decoded and no network request is made. Attachments expose only their
decoded size, declared media type, filename and SHA-256, not their contents.
Embedded `message/rfc822` parts are treated as opaque attachments.

Limits are 32 MiB per source, 64 KiB per header block, 1,024 headers in the message,
16 nested multipart containers and 256 MIME parts. Plain/HTML source uses chunks
of at most 256 KiB, preserving UTF-8 boundaries and the original bytes, with a
bounded 4 KiB lookahead for mapping across chunk boundaries. Structural limits
reject the message rather than silently trimming it. The pure mapping extracts
up to 127 HTTP(S) URLs per text chunk, each at most 4,096 bytes; unsupported or
excess values produce a coverage diagnostic while the original body is retained.
UTF-8 and US-ASCII body text are decoded; other charsets retain original hex bytes
with an explicit coverage notice. Unsupported transport encodings and malformed
multipart structures fail clearly. Minimal recognized headers require analyst
selection; a filename alone never proves the format.

Timestamps use the original Date only with a validated explicit supported zone;
missing, duplicate, invalid or unsupported dates remain unknown. Neither the machine clock
nor file mtime supplies an event time. MIME transformations may prevent an exact
original byte offset for a subrecord. Such a source uses unavailable origin offsets
consistently; known positions remain in `source_byte_offset` and relative
`header_offsets`, while `decoded_body_offset` never claims to be a file offset.
`mime_part_index` preserves the container relationship.

The mapping uses finite email/file rules in included TOML. Native glue projects
RFC mailbox arrays into validated actor/target observations and retains extraction
entities for literal URLs and a source-hash-based `email_message` identity.
The first From/To addresses populate scalar typed roles; all addresses remain
searchable in the original decoded headers and bounded extraction pairs, with a
coverage diagnostic for additional targets. These are header claims, not proof of
identity. Authentication-Results remains untrusted reported data: IRMind performs
no DNS, SPF or DKIM validation and does not infer event success from it. Message
outcome remains unknown. No process-lifetime identity or permission is introduced.

Sources: [message syntax](https://www.rfc-editor.org/rfc/rfc5322),
[MIME structure](https://www.rfc-editor.org/rfc/rfc2046),
[reported authentication status](https://www.rfc-editor.org/rfc/rfc8601).

## Microsoft Defender exports

Export Advanced Hunting results as CSV or JSON, or save the original Streaming API
JSON from Event Hubs/storage. Streaming envelopes use `records`, the documented
`AdvancedHunting-<table>` category and `properties`; API exports may use `Results`.
The nine supported tables are DeviceProcessEvents, DeviceNetworkEvents,
DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents,
DeviceEvents, AlertInfo and AlertEvidence. Project `Table` (or `$table`/`Type`) in
exports when the native columns do not uniquely identify the table. A filename
never supplies table identity. Unidentified layouts and actions retain the original
fields without invented classification.

The decoder preserves field names/types and timestamp precision. Advanced Hunting
Timestamp is UTC; no machine clock or file mtime supplies a timestamp. CSV records
are bounded at 4 MiB/1,024 fields with multiline framing; JSON uses the shared
bounded reader, including arrays/documents with a first line larger than 4 MiB.
Source and record-count limits remain those of the common decoder contract.

Classification, explicit outcomes and roles are included finite TOML tables.
The mapping module's native code only selects a table and reports unsupported
optional values; it contains no action heuristics. DeviceId supplies host
partitioning. Process and parent observations use source-record scope, including
PID reuse; ProcessUniqueId is retained in the original, not promoted to process
lifetime. Sysmon ProcessGuid remains the only supported process-lifetime source.
Incoming network roles reverse only for the documented inbound action; unknown
network actions retain their raw endpoints without guessing a direction.
ConnectionSuccess describes the transport event and does not prove that Network
Protection allowed the application request. AlertInfo and AlertEvidence are source
alerts, never analyst-confirmed findings.

Sources: [Advanced Hunting tables](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables),
[Streaming envelope](https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub),
[process fields](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table),
[network fields](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicenetworkevents),
[Network Protection interpretation](https://learn.microsoft.com/en-us/defender-endpoint/network-protection).

## CrowdStrike Falcon Data Replicator

`parser-fdr` decodes native JSON lines downloaded from the FDR S3 data feed, in
plain text or gzip. Export/download with the provider's tools, then ingest the
local file; this parser does not contact CrowdStrike or fetch S3 objects. The
[provider's FDR integration guide](https://www.crowdstrike.com/wp-content/uploads/2021/06/CrowdStrike-Falcon-Data-Replicator-Technical-Add-On-Guide.pdf)
describes the feed and event filtering. Preserve `event_simpleName`, `timestamp`,
`cid`, `aid` and the original event fields. Native `timestamp` is milliseconds;
other original time fields remain available without reducing their precision.

The independent `mapping-fdr` module uses included finite TOML definitions for
ProcessRollup2/SyntheticProcessRollup2, NetworkConnectIP4/6, NetworkListenIP4/6,
DnsRequest, UserLogon/UserLogonFailed2, PeFileWritten and registry/ASEP updates.
The [provider's FDR dashboards](https://library.humio.com/integrations/integrations-crowdstrike-fdr-crowdstrike-fdr.html)
document process/context joins, endpoints, DNS, file writes and ASEP fields.
Names with no finite rule remain original searchable records, without invented
classification; rename variants without a confirmed field contract stay
unclassified. Optional values that cannot be validated produce a coverage notice.
Source detections do not become analyst-confirmed findings.

Native Falcon process IDs use the explicit `cid` plus `aid` namespace. OS PIDs
remain local to the source record; no Sysmon-style lifetime is inferred.
`aid` supplies the host partition, including its bounded overflow bucket; `cid`
is identity metadata, not a cloud account. Compressed streams have no invented
physical record offsets. Line, JSON depth/field, source and cancellation limits
apply to both encodings. The [compressed admission contract](development/fdr-compressed-admission.md) details the
FDR-only decoded ceiling, CRC validation and disk reservation.

The synthetic [FDR performance sample](development/benchmark-data/fdr-v055.json)
uses an unpadded 1 GiB release build: 2,329,158 records, 63.340 s and 16.167 MiB/s;
post-ingest verification passes outside the timed interval. It is one local
sample, not a speedup comparison. AddressSanitizer completes 1,121,240 executions
in 601 s without failures. The 1/64/1,024/1,025-host tests keep the cap of 64 and
retain original values in overflow.

## macOS exports

Export a bounded window from a Mac with the system `log` command. Choose the
JSON array or line-delimited JSON style. The second example reads an existing
archive. Keep the export and record the host and collection window separately. IRMind consumes the JSON
export. The native binary formats `.logarchive` and `tracev3` are outside this
parser's input. [Apple's guide to viewing Unified Log messages](https://developer.apple.com/documentation/os/viewing-log-messages)

```sh
log show --last 1h --timezone UTC --style ndjson > unified.ndjson
log show --archive case.logarchive --last 1h --timezone UTC --style json > unified.json
```

Use the list of Endpoint Security event names shipped with the collector's macOS
version. The analyst runs `eslogger` as superuser from a terminal they have
granted Full Disk Access and stops the collection at the end of the window.
IRMind reads the saved JSON and preserves the outer schema and message versions.
It does not start either Apple collector. [Apple's eslogger walkthrough](https://developer.apple.com/videos/play/wwdc2022/110345/)

```sh
man eslogger
sudo eslogger exec fork exit open create rename unlink openssh_login openssh_logout > endpoint.ndjson
```

The included tables interpret schema-1 notifications. They cover process
start/exit, file activity, authentication, login/logout, SSH, sudo and su,
mounts, TCC, XProtect and Gatekeeper where the selected OS emits those events.
Explicit login results map to success, failure or unknown. Process IDs stay
record scoped and the text of Unified Log messages stays original evidence.
Unknown event types and schemas retain their original fields. XProtect detection
notifications remain unconfirmed findings. The precision of an exported
timestamp is retained, including the nanosecond remainder where supplied.

## Google Workspace Reports API

Collect a bounded period with the Admin SDK Reports API v1 `activities.list`
using an audit-read identity. Save each response page as JSON. Alternatively,
save individual activities as a JSON array or NDJSON. Retain the collection
window, requested application and pagination record with the originals.
IRMind reads the saved files locally. [Google Reports API reference](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list)

Each activity yields one record per member of its `events` array, up to 128
members. The input offset points at the original activity, and the event ordinal
distinguishes records within the indexed source. The activity ID, actor and
each event's original parameter arrays stay in evidence.

The included mappings cover login and SAML outcomes, administrator and account
changes, OAuth consent, Drive downloads and sharing, and Gmail delivery
subtypes when provided. Use the Gmail native event code to distinguish manual
forwards (10) and automatic forwards (11). Unknown events remain searchable
as original data. [Google Gmail activity reference](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gmail)

## Route 53 VPC Resolver

Configure [VPC Resolver query logging](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html) and export original JSON events from its log destination. Ingest objects, arrays, or NDJSON. The decoder preserves `query_timestamp` precision. The mapping provides DNS and outcome filters for known response codes. The [native answer records](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-example-json.html) remain searchable in the original fields. AWS supplies record type, class and RDATA with each answer.

## GitHub audit log

In the organization or enterprise audit log, select a bounded time range and
export JSON or CSV. For audit log streaming, collect the native JSON records from
the configured destination. Save the original downloads and collection scope.
Unpack a compressed delivery before ingesting its NDJSON as a separate source.
Visibility of source IPs and Git events depends on the export and audit
settings. [GitHub organization audit export](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization) · [GitHub enterprise audit export](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/exporting-audit-log-activity-for-your-enterprise)

The module preserves the native event time, actor, organization, repository,
user agent and source IP when present. It maps documented role and access
changes, token and key events, repository transfers, visibility and removals,
Git downloads, and Actions policies and secret metadata. Values such as
`hashed_token`, `token_scopes` and `programmatic_access_type` are original
evidence fields. The decoder makes no GitHub request and keeps unknown actions
searchable. [GitHub's audit event reference](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
