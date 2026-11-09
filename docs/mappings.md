# Source mapping modules

For analysts and contributors, this page explains how optional common-event mappings interpret decoded logs. Parsers decode formats; mappings classify events and assign entity roles. A classification never grants permission or confirms a finding.

The common writer is currently experimental and opt-in during the decoder rollout. Pre-1.0 formats may change between minor versions without migration; keep the creating IRMind version or re-ingest verified originals into a new case. New mappings apply to new ingestions; re-ingest verified originals into a new case to change a source's interpretation. See the [pipeline design](development/source-mapping-design.md) and [security model](security-model.md).

| Module | Input | Implementation | Cargo feature | Status |
| --- | --- | --- | --- | --- |
| CloudTrail | CloudTrail JSON through `json-source-v1` | Bundled, hash-pinned TOML | `mapping-cloudtrail` | Experimental; synthetic contracts |
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

Five mapping modules share the `mapping-linux` feature. The sshd, sudo, su and HTTP modules use bundled TOML definitions with fixed canonical hashes. Each has a separate manifest and disjoint dataset selector. The auditd module is native because it must join a bounded set of original SYSCALL/EXECVE members; a finite field table cannot perform that join. Journald keeps its extraction-only mapping through the same Linux decoder, without inventing classifications.

- SSH `Accepted`, `Failed` and `Invalid` token values select explicit authentication outcomes. Unknown messages stay unclassified. A successful user is the actor; the attempted account on a failure is the target.
- PAM session `opened` and authentication `failure` values use explicit outcome tables. Closing a session does not imply a new authentication result. A sudo command request has unknown outcome: requesting a command does not prove that it ran successfully.
- User identities use the reported host namespace. Reused PIDs use source-record identities unless a true process-lifetime identifier exists. The same username in actor and target fields remains one identity with two observations.
- Auditd uses explicit `success=yes/no` only for complete groups. Missing status and partial groups remain unknown. Original architecture, syscall and arguments remain available; no architecture-specific syscall interpretation or shell command is invented.
- HTTP 2xx/3xx statuses map to success, 4xx/5xx to failure and 1xx to unknown. The original `-` user marker is retained, and `omit_text` prevents it from becoming a user identity. HTTP logs do not establish a server hostname, so the mapping does not invent a host partition.

Malformed IPs, ports and other typed values retain the shared boundary's unsupported-value diagnostic and original source record. These mappings do not infer results from arbitrary message substrings and do not grant tools any permission.
