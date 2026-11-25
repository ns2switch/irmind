# Local Sigma detection

[Español](es/sigma.md)

IRMind evaluates a bounded subset of Sigma detection rules over the authenticated local Parquet artifacts of an open case. The signed run records the admitted rule bytes, the source scope, the reviewed field table, skipped rules and exact evidence rows. Evaluation uses local evidence and runs without a model or network connection.

## Run a pack

1. Put your reviewed single-document YAML rules in a local directory. Establish the pack's provenance and license before importing third-party rules.
2. Run `/sigma inspect <directory>` and review the manifest SHA-256. Use `/sigma import --license <license-id> <directory>` and confirm that hash to sign the admission.
3. Run `/sigma run <manifest SHA-256> <start UTC> <end UTC>`. Use two increasing UTC timestamps, for example `2026-11-01T00:00:00Z 2026-11-02T00:00:00Z`.
4. Review the proposed matches and their row references. Use `/confirm <finding-id>` to confirm an individual finding before publishing the case report.
5. Run `/verify` to check the authenticated case and its Sigma material. Seal the case before exporting V10. The recipient can verify the export using the case's expected analyst key fingerprint.

Sigma compiles the full rule independently for each applicable source class and runs it where all fields have exact bindings. The signed run records skipped class and rule pairs and distinguishes coverage gaps from indeterminate rows and interrupted scans. An empty result leaves activity in any skipped class undetermined.

Of the 3,302 files in the pinned SigmaHQ r2026-07-01 release, 3,301 passed pack admission and 1,022 compiled for all applicable classes in the reviewed field table. See the [counts and rejection reasons by family](development/benchmarks/sigmahq-v070-admission.md).

The [v0.7.3 table-only audit](development/benchmarks/sigmahq-v073-reviewed-fields.md) compiled 1,159 of the same 3,302 rules with the V2 evaluator. The audit records the effect of each block separately.

Compare the [V2 and V3 admission and scan measurements](development/benchmarks/sigma-v073-source-classes.md) for the same reviewed table.

## Source coverage and field names

Use the indicated `product` and `service` as Sigma logsource selectors. Category selectors narrow the listed source classes. Field names in the third column are case-sensitive. Text and numeric values follow the listed binding types.

| Product and service | Enrolled events | Field examples |
| --- | --- | --- |
| `windows/security` | Security channel and the enrolled audit event IDs; category `process_creation` for 4688 | `EventID` and `LogonType` (integers), `Channel`, `Computer`, `SubjectUserName`, `TargetUserName`, `IpAddress`, `SourceIp` (IP); 4688 also `Image`, `ParentImage`, `CommandLine` |
| `windows/sysmon` | Microsoft-Windows-Sysmon/Operational, IDs 1, 3, 11, 22 | `Image`, `CommandLine`, `ParentImage`, `ProcessGuid`, `OriginalFileName`, `Hashes` and `IntegrityLevel` for process creation; `SourceIp`, `DestinationIp`, `TargetFilename` and `QueryName` in their respective event classes |
| `windows/sysmon` | Image load ID 7 and registry IDs 12–14 | `ImageLoaded`, `OriginalFileName`, `Signed` and `SignatureStatus` for image load. `TargetObject`, `EventType`, `Details` or `NewName` as supplied by the specific registry class |
| `windows/powershell` | Microsoft-Windows-PowerShell/Operational, 4103 module logging and 4104 script block logging | `EventID` (integer), `Payload`, `ContextInfo`, `ScriptBlockText`, `ScriptBlockId`, `Path` by class |
| `linux/sshd`, `linux/sudo`, `linux/su` | Mapped auth.log or secure authentication; sudo process starts | `Outcome`, `Hostname`, `User`, `TargetUser`, `Message`, `Process`, `PID`; SSH also `Verb`, `LoginUser`, `SourceIP`, `SourcePort` |
| `linux/auditd`, `linux/ecs` | Grouped auditd records and Linux ECS authentication or process starts, including Elastic ECS | `Syscall`, `Serial` and `Node` in auditd; typed `Image` and `ProcessId` in process classes; ECS authentication also `SourceIP` and `Outcome` |
| `aws/cloudtrail` | Operations in the reviewed CloudTrail table | `eventName`, `eventSource`, `sourceIPAddress` (original text), `source.ip` (IP), `awsRegion`, `recipientAccountId`, `userIdentity.principalId`, `userIdentity.arn`, `errorCode`, `readOnly`, `Outcome`, `requestParameters.userName`, `requestParameters.roleArn`, `requestParameters.policyArn`, `responseElements.ConsoleLogin` |
| `zeek/dns`, `zeek/http`, `zeek/conn` | JSON and TSV DNS, HTTP and connections | `id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`, `proto`, `query`, `qtype_name`, `rcode_name`, `host`, `uri`, `method`, `status_code` by class |
| `suricata/dns`, `suricata/http`, `suricata/flow`, `suricata/alert` | EVE DNS, HTTP, flow and alert | `src_ip`, `dest_ip`, `src_port`, `dest_port`, `event_type`, `dns.rrname`, `http.hostname`, `http.status`, `alert.signature`, `alert.signature_id` by class |
| `windows/iis` | IIS W3C, `webserver` | `cs-method`, `cs-uri-stem`, `cs-uri-query`, `sc-status`, `cs-user-agent`, `cs-username`, `cs-host`, `cs-referer`, `cs-content-type`, `c-ip` |
| `aws/route53`, `windows/dns-debug` | Route 53 Resolver and Windows DNS debug, `dns` | `query`, `record_type`, `rcode`, `source.ip`, plus `destination.ip` for Windows DNS debug |
| `azure/signinlogs`, `azure/auditlogs`, `azure/activitylogs` | Entra sign-in and audit exports, AzureActivity table | `ResultType` (text), `IPAddress` (IP), `UserPrincipalName`, `AppId`, `OperationName`, `Result`, `InitiatedBy.user.userPrincipalName`, `OperationNameValue`, `ActivityStatusValue`, `CallerIpAddress` by layout |
| `m365/audit`, `m365/exchange` | Unified Audit Log and explicit Exchange workload | `Operation`, `Workload`, `UserId`, `ClientIP`, `ObjectId`, `ResultStatus`, `Outcome`; Exchange also supports `Parameters` |
| `okta/okta` | Okta System Log | `eventType`, `outcome.result`, `actor.alternateId`, `client.ipAddress`, `SourceIP`, `Outcome` |
| `gcp/gcp.audit` | Cloud Audit Logs | `protoPayload.methodName`, `protoPayload.serviceName`, `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp`, `protoPayload.status.code` (integer, absent if missing) |
| `kubernetes/audit` | Kubernetes audit, EKS, AKS and GKE | `objectRef.resource`, `objectRef.namespace`, `Outcome`; native, EKS and AKS also `verb`, `user.username`, `responseStatus.code`, `PrimarySourceIP`, `sourceIPs` (IP list), `stage`; GKE also `protoPayload.methodName` and `protoPayload.status.code` (integer) |
| `windows/defender` | Defender process creation and connections with explicit Windows platform evidence | `Image`, `ParentImage`, `CommandLine`, `ParentCommandLine`, `FileName`, `FolderPath`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`; network `LocalIP`, `RemoteIP`, `LocalPort`, `RemotePort` |
| `windows/crowdstrike` | Windows FDR process rollups and IP4 or IP6 connection events | `Image`, `CommandLine`, `ParentBaseFileName`, provider-scoped `TargetProcessId` and `ParentProcessId`, `aid`, `cid`; the matching family of `LocalAddressIP4` / `RemoteAddressIP4` or IP6 |
| `macos/eslogger` | eslogger v1 notification exec and file creation | `Image` from the exec target, `Arguments` as a list, `ProcessId`, `TargetFilename` and `ActorExecutable` by class |

In Exchange rules, a `Parameters` mapping with `Name` and `Value` matches both in the same parameter entry. Defender's `Image` and `ParentImage` use the original path when it already names the executable and agrees with the corresponding filename. A directory-only value leaves that field absent.

An indeterminate row has an exact field that a rule needs but cannot evaluate. Kubernetes, EKS and AKS keep the event when `sourceIPs` contains more than 32 entries, duplicates, invalid addresses or an unexpected type. GKE also keeps events when the original status code has an unexpected type or falls outside the accepted range. Check the per-source and per-rule counts in the TUI and consult the original evidence. These values may indicate source manipulation. The report cites the signed run and explains the partial coverage.

The reviewed tables list every admitted field, original path, typed column and selector. [CloudTrail](../crates/infra/src/sigma_pack/cloudtrail-v1.toml) · [Windows](../crates/infra/src/sigma_pack/windows-v1.toml) · [Linux](../crates/infra/src/sigma_pack/linux-v1.toml) · [Network](../crates/infra/src/sigma_pack/network-v1.toml) · [Cloud identity](../crates/infra/src/sigma_pack/cloud-identity-v1.toml) · [Endpoint](../crates/infra/src/sigma_pack/endpoint-v1.toml)
