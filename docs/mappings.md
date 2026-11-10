# Source mapping modules

For analysts and contributors, this page explains how optional common-event mappings interpret decoded logs. Parsers decode formats; mappings classify events and assign entity roles. A classification never grants permission or confirms a finding.

The common writer is currently experimental and opt-in during the decoder rollout. Pre-1.0 formats may change between minor versions without migration; keep the creating IRMind version or re-ingest verified originals into a new case. New mappings apply to new ingestions; re-ingest verified originals into a new case to change a source's interpretation. See the [pipeline design](development/source-mapping-design.md) and [security model](security-model.md).

| Module | Input | Implementation | Cargo feature | Status |
| --- | --- | --- | --- | --- |
| CloudTrail | CloudTrail JSON through `json-source-v1` | Bundled, hash-pinned TOML | `mapping-cloudtrail` | Experimental; synthetic contracts |
| Windows Event Log | Original EVTX through `evtx-source-v1` | Bundled, hash-pinned per-event/channel TOML modules | `mapping-evtx` | Experimental; synthetic contracts |
| OCSF | Original JSON or Parquet through `ocsf-source-v1` | Native, typed OCSF 1.4 validation | `mapping-ocsf` | Experimental; synthetic contracts |
| ECS | Original ECS NDJSON through `ecs-source-v1` | Native, typed ECS 9.5 validation | `mapping-ecs` | Experimental; synthetic contracts |
| Generic JSON compatibility | Other JSON without `eventVersion` | Native, extraction-only | `mapping-json-compat` | Experimental; no inferred categories or roles |
| Journald compatibility | Original journald JSON | Native, extraction-only | `mapping-journald-compat` | Experimental; no inferred categories or roles |
| Linux authentication | auth.log and secure: sshd, sudo and su | Bundled, hash-pinned TOML | `mapping-linux` | Experimental; synthetic contracts |
| Linux auditd | Original grouped SYSCALL and EXECVE members | Native, bounded cross-member projection | `mapping-linux` | Experimental; synthetic contracts |
| HTTP access | nginx and Apache common/combined | Bundled, hash-pinned TOML | `mapping-linux` | Experimental; synthetic contracts |

## CloudTrail

The bundled definition explicitly selects table interpreter V2 and uses explicit service and operation names. `ConsoleLogin` maps the documented `responseElements.ConsoleLogin` values `Success` and `Failure`; an absent result remains unknown. An API result is classified only for listed operations with `eventType = AwsApiCall`: a present `errorCode` means failure; its absence means success. Unlisted operations stay unclassified.

Supported operation families:

| Service | Operations |
| --- | --- |
| Sign-in | ConsoleLogin |
| IAM | CreateUser, DeleteUser, CreateAccessKey, DeleteAccessKey, UpdateAccessKey, CreateLoginProfile, UpdateLoginProfile, AttachUserPolicy, DetachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy, AddUserToGroup, CreatePolicyVersion, SetDefaultPolicyVersion |
| STS | AssumeRole, AssumeRoleWithSAML, AssumeRoleWithWebIdentity, GetCallerIdentity |
| EC2 | RunInstances, StartInstances, StopInstances, AuthorizeSecurityGroupIngress |
| S3 | GetObject, PutObject, DeleteObject |
| CloudTrail | StopLogging, StartLogging, UpdateTrail, DeleteTrail |

Actor identities use the actor's account namespace. A requested target user uses the recipient account namespace. A name present in both roles remains two observations, rather than two global identities. API parameters never become process lifetime identities. Account/region partitions retain the existing normalization, cardinality and scope checks.

Only valid IP values populate `source.ip`. A service name in `sourceIPAddress`, an invalid typed field or an unsupported source representation produces an explicit unclassified projection through the shared mapping boundary. The original record remains available. Missing values are never invented.

The default compiled catalog uses disjoint selectors: the CloudTrail definition requires `eventVersion`; generic compatibility requires that field to be absent. Records with a null version match neither. Installing an overlapping definition is rejected; there is no priority or silent fallback. The broad extraction-only constructor remains available to pinned compatibility benchmarks.

The definition's canonical digest is fixed in the module. Changing its interpretation requires a reviewed version and digest. Its exact identity and the target common schema are bound by the existing V3 mapping profile and receipt. Definitions run without file, network, clock or secret ports.

References: [CloudTrail record fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html), [console sign-in events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html), and [IAM/STS CloudTrail events](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html).

## Optional absent-value markers

In table definitions, a field may declare `omit_text = ["", "-"]` for documented source markers. A matching original string omits only that projected field and its entity observation. Original evidence is unchanged. Matching is exact and case-sensitive; invalid values not listed still fail validation. Lists contain at most eight distinct, control-free literals of at most 256 UTF-8 bytes each. See the [bounded interpreter design](development/mapping-optional-fields.md).

## Linux authentication, auditd and HTTP

`parser-linux` decodes original fields through `linux-source-v1`. The decoder preserves original messages, exact timestamps and member locations; it never assigns a category, outcome or entity role. Classic auth.log/secure timestamps still require confirmed per-ingestion year and UTC-offset context. The same detector and confirmation flow serve the CLI and TUI.

Six mapping modules share the `mapping-linux` feature. The sshd, sudo, su and HTTP modules use bundled TOML definitions with fixed canonical hashes. Each has a separate manifest and disjoint dataset selector. The auditd module is native because it must join a bounded set of original SYSCALL/EXECVE members; a finite field table cannot perform that join. Journald keeps its extraction-only mapping through the same Linux decoder, without inventing classifications.

- SSH `Accepted`, `Failed` and `Invalid` token values select explicit authentication outcomes. Unknown messages stay unclassified. A successful user is the actor; the attempted account on a failure is the target.
- PAM session `opened` and authentication `failure` values use explicit outcome tables. Closing a session does not imply a new authentication result. A sudo command request has unknown outcome: requesting a command does not prove that it ran successfully.
- User identities use the reported host namespace. Reused PIDs use source-record identities unless a true process-lifetime identifier exists. The same username in actor and target fields remains one identity with two observations.
- Auditd uses explicit `success=yes/no` only for complete groups. Missing status and partial groups remain unknown. Original architecture, syscall and arguments remain available; no architecture-specific syscall interpretation or shell command is invented.
- HTTP 2xx/3xx statuses map to success, 4xx/5xx to failure and 1xx to unknown. The original `-` user marker is retained, and `omit_text` prevents it from becoming a user identity. HTTP logs do not establish a server hostname, so the mapping does not invent a host partition.

Malformed IPs, ports and other typed values retain the shared boundary's unsupported-value diagnostic and original source record. These mappings do not infer results from arbitrary message substrings and do not grant tools any permission.


## Elastic Common Schema

`parser-ecs` preserves original ECS JSON fields through `ecs-source-v1`.
The separate `mapping-ecs` module validates explicit category/type sets,
outcomes, addresses, ports and other supported common fields. It does not infer
classifications from action or message text. Unknown labels stay in the source
and produce diagnostics; missing outcome remains unknown.

Source and destination addresses retain their roles. Actor and target users use
explicit directory, host and account/project qualifiers; an absent directory namespace
keeps identities local to their source record. Process PIDs always use source-record
scope. Names and producer IDs remain searchable context, without inventing a
process lifetime. Conflicting dotted and nested aliases are unsupported.

The extraction projection preserves existing search aliases and original
attributes. The native implementation is required for bounded sets, typed values
and alias validation. See the [ECS pipeline design](development/ecs-source-mapping.md)
for exact identity rules and [supported fields](development/common-event-schema.md).

## Windows Event Log

`parser-evtx` exposes original decoded fields through `evtx-source-v1`, using
its existing isolated helper, authenticated seekable handle and bounded protocol.
Timestamps retain 100 ns precision. Original record IDs and measured offsets stay
in provenance. Windows still schedules EVTX sources serially; both routes share
the same session isolation witness. The helper, permissions and signed formats remain unchanged.

Bundled TOML modules select exact provider/channel pairs. Security also selects the original EventID; each ID has an independent, bounded table:

| Provider / channel | Event IDs |
| --- | --- |
| Microsoft-Windows-Security-Auditing / Security | 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4720, 4722, 4724, 4728, 4732, 4756, 4768, 4769, 4771, 4776 |
| Service Control Manager / System | 7045 |
| Microsoft-Windows-PowerShell / Microsoft-Windows-PowerShell/Operational | 4103, 4104 |
| Microsoft-Windows-Sysmon / Microsoft-Windows-Sysmon/Operational | 1, 3, 11, 13, 22 |

Security identities use event-specific roles and reported directory namespaces.
On successful logon/logoff, the reported logged-on account is the actor; the
reporting service remains a separate source identity on 4624. On a failed logon,
the subject and attempted account remain actor and target. Group membership
events keep the member user separate from the target group resource. Events 4771 and 4776 lack a target directory field; their
names use the reporting host namespace. Missing fields remain absent. Event 4776
never invents a source IP from its workstation name. Security 4688 process and
parent PIDs use source-record scope. Only the original Sysmon ProcessGuid and
ParentProcessGuid supply process-lifetime identities; PIDs remain context and
never substitute for a GUID. Exact `-` markers omit only the projected field,
while the original source stays searchable.

Event 4625 and 4771 are failures. Event 4648 records an attempt, not confirmed
success. Password reset (4724) uses explicit Audit Success/Failure keywords. Ticket and
credential validation (4768, 4769 and 4776) use finite, documented Status tables,
with audit keywords only when Status is absent. An absent state stays unknown;
unlisted status codes remain original and unclassified. PowerShell
and Sysmon activity does not establish an authentication result. Unsupported IDs
stay unclassified; a different or missing provider never matches by channel alone.

Field and outcome references: Microsoft's [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625),
[4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648),
[4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688),
[4724](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724),
[4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768),
[4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769),
[4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776),
[PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
and [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) documentation.

## Open Cybersecurity Schema Framework

`parser-ocsf` emits original typed fields, measured byte offsets for JSON,
and full source timestamp precision. Local Parquet uses the original open file;
its row ordinal is recorded without inventing a byte offset. Both formats use
`ocsf-source-v1`.

The separate `mapping-ocsf` module validates OCSF **1.4.0** class/category pairs
for File Activity (1001), Process Activity (1007), Detection Finding (2004),
Authentication (3002), Network Activity (4001) and API Activity (6003). Explicit
status IDs 1/2 mean success/failure; missing, unknown, other or conflicting
status remains unknown. Activity and status tables never interpret message text.
Other schema versions and unsupported class/category pairs remain unclassified,
with diagnostics and their original searchable fields and extraction aliases.

In Authentication, `actor.user` and root `user` map to actor and target; endpoints retain source
and destination roles. Directory, host and account qualifiers namespace users.
An absent directory keeps a user local to its source record. Only Process Activity maps root process and parent fields. Their
PIDs always use source-record scope, including reused PIDs: a UID is retained
as context, without assuming that it proves a process lifetime. Detection
Finding is source telemetry and never confirms a case finding.

The native implementation validates nested typed values and class/category
relationships that finite field tables cannot express. It follows the
[pinned OCSF schema](https://github.com/ocsf/ocsf-schema/tree/v1.4.0),
including the documented [authentication roles](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/events/iam/authentication.json).

## DFIR tool output extraction

The `mapping-dfir` feature includes five independently identified extraction
modules: Velociraptor, Hayabusa, Chainsaw, plaso and EZTools. Their source
decoders retain original JSON types or CSV columns, record locations and exact
timestamp precision. A custom field named `events` remains data; it is not a
record wrapper. Invalid rows are counted with bounded untrusted samples.

These modules preserve existing search aliases, correlation relations and host
partitioning without inferring categories, outcomes or entity roles. Hayabusa
rule names remain source telemetry; they do not confirm a case finding. Plaso
keeps its numeric microsecond timestamp and original `parser` and `data_type`.
EZTools retains the detected tool and its original columns. Documented UTC CSV
timestamps do not use the machine clock or file modification time.

The projections are native because they preserve tool-specific nested aliases,
CSV layouts and correlation relations that the finite classification tables do
not express. They have separate manifests and pinned build identities. Shared
contracts test repeated and concurrent decoding, provenance, cancellation and
deterministic mapping; parity fixtures check the existing search identities and
timestamps. Both the ordinary ingestion route and reconstruction use the same
source decoder and mapping selected for each signed source.

## Syslog extraction

`parser-syslog` decodes RFC 5424 and RFC 3164 headers and messages through
`syslog-source-v1`, including bounded gzip streams. `mapping-syslog` is a
separate extraction-only module. Header host, application, PID, facility and
severity aliases remain searchable; none implies a common-event category,
outcome or entity role. RFC 5424 retains the timestamp's full source precision.
RFC 3164 requires the same confirmed per-ingestion calendar as ordinary syslog
ingestion, including the explicit December-to-January rollover option. The
calendar remains signed in the source selection. No clock or mtime is used.

Gzip records retain their decoded member ordinal and source hash. They do not
claim a byte offset inside the compressed original. The common writer uses the
same source decoder for ingestion and reproducible verification. Bounded
rejection samples remain untrusted content.

Linux account-management and cron messages use a separate unclassified
extraction module under `mapping-linux`. It preserves the existing user,
command, host, process and PID search aliases for `useradd`, `usermod`, `cron`,
`crond` and `CRON`. Finite selectors keep it disjoint from sshd, sudo and su.
Its bounded native extraction reads the original message layout; it assigns no
category, outcome or process lifetime. A request in a cron log does not prove
that a command succeeded.

## Zeek and Suricata extraction

The source decoders preserve original Zeek JSON and TSV fields and Suricata EVE
JSON. Zeek TSV retains its original column strings and declared types as two
separate objects; the format discriminator records the header's dataset. Decimal
Zeek timestamps retain microseconds or nanoseconds without floating-point
rounding. EVE numeric UTC offsets are parsed explicitly.

The `mapping-network` feature provides separately identified Zeek and Suricata
extraction modules. They retain UID/flow correlation, endpoints, domains,
certificates, files and source detection aliases. These modules do not infer
common-event categories, outcomes or roles. A source alert remains telemetry;
it does not confirm a case finding. Native extraction preserves literal dotted
Zeek field names, TSV nil markers and source-specific correlation relations that
are not classification-table operations.

The existing bounded record framing, source-size limits, measured offsets,
cancellation and untrusted rejection samples apply to both ingestion and
reconstruction. No original fields are recovered from normalized display text.
