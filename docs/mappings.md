# Source mapping modules

For analysts and contributors, this page explains how optional common-event mappings interpret decoded logs. Parsers decode formats; mappings classify events and assign entity roles. A classification never grants permission or confirms a finding.

The common writer is experimental and opt-in. Existing V1/V2 cases stay readable without migration. New mappings apply to new ingestions; re-ingest verified originals into a new case to change a source's interpretation. See the [pipeline design](development/source-mapping-design.md) and [security model](security-model.md).

| Module | Input | Implementation | Cargo feature | Status |
| --- | --- | --- | --- | --- |
| CloudTrail | CloudTrail JSON through `json-source-v1` | Bundled, hash-pinned TOML | `mapping-cloudtrail` | Experimental; synthetic contracts |
| Generic JSON compatibility | Other JSON without `eventVersion` | Native, extraction-only | `mapping-json-compat` | Experimental; no inferred categories or roles |
| Journald compatibility | Original journald JSON | Native, extraction-only | `mapping-journald-compat` | Experimental; no inferred categories or roles |

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
