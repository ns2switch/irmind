# Local Sigma detection contract

**Status.** The v0.7 design is approved. The proposed V10 wire vectors and
YAML parser dependency require separate approval.

## Rule admission and coverage

Evaluate the detection-rule subset of Sigma 2.1 on authenticated Parquet event
partitions of one case. A deterministic compiler and evaluator perform a run
without a model. Correlations, aggregations across events, Sigma filters as
separate documents, external lookups, arbitrary backend queries and executable
processing pipelines are outside the supported subset. Compile Boolean
selections, named wildcards, quantifiers, grouping and negation to a typed AST.
Pin the upstream specification version and adopt its selection and condition
precedence. [Sigma rule specification](https://github.com/SigmaHQ/sigma-specification/blob/v2.1.0/specification/sigma-rules-specification.md)

A reviewed versioned declarative table resolves the exact `product`,
`service` and `category` to parser, dataset/channel, required event types
and field semantics. Omitted selectors may cover the explicit union declared
by the table. A rule must resolve every field on every selected source class.
Unsupported logsource, ambiguous mapping, unsupported field/operator,
incomplete projection or unavailable selected evidence makes the whole rule
ineligible for that plan. Report the rule ID, selector and reason. A
semantically supported but absent field in an individual event is a separate
condition, handled by the operator's pinned semantics.

| Proposed source coverage | Example mappings |
| --- | --- |
| Windows EVTX Security, Sysmon, and PowerShell with explicit channels | `EventID` to the provider-scoped event code. `Image` and `ParentImage` to executable paths on process events. `CommandLine` to the appropriate typed role. Explicit original event-data paths for `LogonType` and `ScriptBlockText`. |
| Linux auth.log, auditd, and mapped ECS sources | Authentication and process selectors scoped to their applicable sources. Common fields carry IPs and user roles. Audit record fields use source-specific typed original-field allowlists. |
| CloudTrail | CloudTrail operation and provider selectors. `eventName` retains the exact original operation. Identity and source IP use the approved mappings where equivalent. |
| Zeek and Suricata | Explicit DNS, HTTP and connection subsets. The DNS question and network endpoint roles use the common projection. Source detection alerts retain their original attribution. |

The initial coverage includes these explicit source-class proposals. Names
and exact types on the right are checked against the retained projection for
the enrolled decoder and mapper pair before admitting a rule. A missing
path contract makes the rule ineligible for that source class.

| Sigma logsource | Admitted events and exact field bindings |
| --- | --- |
| `azure`, `signinlogs` | Entra interactive and noninteractive sign-in sources. `ResultType` to the original response code in its Sigma type for each source, `IPAddress` to source IP, `UserPrincipalName` to the original UPN, and `AppId` to the original application ID. |
| `azure`, `auditlogs` | Entra AuditLogs. `OperationName`, `Result` and `InitiatedBy.user.userPrincipalName` use original typed fields. Application and user actors remain distinct. |
| `azure`, `activitylogs` | AzureActivity. Admit `OperationNameValue`, `ActivityStatusValue` and `CallerIpAddress` where the enrolled variant retains those forms. Display names and codes are separate bindings. |
| `m365`, `audit` | Unified Audit Log. `Operation`, `Workload`, `UserId`, `ClientIP` and `ResultStatus` use AuditData values. Admit alternate SigmaHQ service names only through table rows with verified semantics. |
| `okta`, `okta` | Okta System Log. `eventType`, `outcome.result`, `actor.alternateId` and `client.ipAddress` use original fields. |
| `gcp`, `gcp.audit` | Cloud Audit Logs. `protoPayload.methodName`, `protoPayload.serviceName`, `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp` and `protoPayload.status.code` use original typed bindings. An absent status remains absent. |
| `kubernetes`, `audit` | Native, EKS, GKE and AKS audit classes with a proven native equivalent for each field. `verb`, `objectRef.resource`, `objectRef.namespace`, `user.username`, `sourceIPs` and `responseStatus.code` bind to the decoded audit event. `sourceIPs` preserves its list semantics. |
| `windows`, `process_creation` from Defender | Versioned `DeviceProcessEvents` creation events with proven Windows source metadata. `Image` uses the exact executable path assembled by its mapping. `CommandLine` uses `ProcessCommandLine`, `ParentCommandLine` uses `InitiatingProcessCommandLine` and `ParentImage` uses the exact initiating process path. |
| `windows`, `process_creation` from CrowdStrike FDR | `ProcessRollup2` and `SyntheticProcessRollup2` with proven Windows platform. `Image` to `ImageFileName` and `CommandLine` to the source `CommandLine`. `ParentImage` requires an exact parent-path field from that schema, or the rule is ineligible. Process IDs retain the provider scope. |
| `macos`, `process_creation` from eslogger | Endpoint Security exec events. `Image` to `event.exec.target.executable.path`, `ParentImage` to the executing actor path only where the precise parent semantics are proven. Exec argument vectors are lists. A rule requiring an unavailable scalar command line is ineligible. A fork does not satisfy exec-only predicates. |

Use distinct source rows for other proven categories, such as Defender
network connection with `LocalIP`, `RemoteIP`, `LocalPort`, `RemotePort`;
FDR network connections with `LocalAddressIP4` or `LocalAddressIP6` and the
same-family `RemoteAddressIP4` or `RemoteAddressIP6`; and eslogger file
creation with the exact destination path when available. Never substitute
process names for paths or a PID for a stable process identity.
[Sigma logsource taxonomy](https://github.com/SigmaHQ/sigma-specification/blob/v2.1.0/specification/sigma-appendix-taxonomy.md)

Every table row names a common column or bounded original-field path with
exact scalar or list semantics, type and null handling. Use original fields
from the authenticated per-event stored projection only where equality to
the source field is proven for the decoder and mapping versions. Where an
original field cannot be resolved from authenticated local evidence within
the budget, reject the rule. Source hashes, frame boundaries and logical
record IDs cannot be supplied by rule strings. Validate the table with one
positive and negative fixture per binding and one unsupported-source test per
product family. [Common event schema](common-event-schema.md)

## Operators and limits

| Class | Initial support and rejection |
| --- | --- |
| Text and lists | Exact values, Sigma wildcards and escaping, `contains`, `startswith`, `endswith`, `all` and explicit case sensitivity. Preserve arrays without implicit joining or string coercion. |
| IP and presence | `cidr` for checked IPv4/IPv6. `exists` distinguishes absent fields from values, including empty and null where specified. Incompatible types are rejected at compile time. |
| Regex | `re` and supported regex flags use the existing Rust finite-automata regex family. Restrict pattern bytes, AST nesting and compiled size, cap subject bytes and charge the matcher. Backreferences, look-around and unsupported flags are rejected. A bounded subject overflow makes the run partial, rather than clipping the value and claiming a complete result. |
| Encodings and command-line variants | `base64` and `base64offset` transform rule values with the pinned Sigma byte semantics. `windash` expands only the documented alternatives. Admit supported typed modifier chains in order, with an aggregate cap on generated alternatives. Reject an over-budget chain in full. |
| Deferred forms | Reject field-to-field comparisons, substitution/placeholders, whole-event keywords without an exact field contract, unsupported encodings and unknown modifiers. Report what failed before scanning. |

Use a bounded YAML event reader, rejecting duplicate keys, custom tags,
anchors, aliases, merge keys and multiple YAML documents per rule. Start
with 4,096 rules per pack, 64 KiB per rule, 64 MiB of pack bytes, a depth
limit of 24, 4,096 syntax events per rule and a 256-branch compiled expansion
cap. Propose a fixed-size, versioned evaluation unit that charges candidate
rows, decoded original-field bytes and predicate work. Reserve before the
scan under bounded per-rule, per-run and case ceilings, share the case broker,
and check time, work and cancellation between bounded batches. A timeout or
cap yields a signed partial status with a precise stop reason. A partial
result makes no claim about unscanned rows. [Sigma modifiers appendix](https://github.com/SigmaHQ/sigma-specification/blob/v2.1.0/specification/sigma-appendix-modifiers.md) ·
[Rust regex complexity and limits](https://docs.rs/regex/latest/regex/#untrusted-input)

## Pack import and execution

Import explicitly from a local pack/directory or from a local copy of a
specific SigmaHQ release archive whose exact SHA-256 the analyst supplies
and confirms. Traverse regular bounded paths inside the chosen input.
Check the archive hash before bounded extraction. Reject links, traversal,
duplicates and expansion overflow. Pin a manifest over normalized relative
names and exact rule bytes. Store original rules, recorded release/tag, pack
hash, rule ID/version, authors and license for independent verification.
Show author attribution alongside matches and retain source and license
notices when sharing rule bytes. Initial tests and benchmarks use only
project-owned synthetic rules. A bundled third-party pack requires separate
license review. [SigmaHQ license](https://github.com/SigmaHQ/sigma/blob/master/LICENSE) ·
[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md)

`/sigma` lists packs, previews exact coverage, evaluates admitted packs and
shows matches, rejections and limits. A model may propose a bounded local
scan by admitted pack ID, rule IDs, selected source scope and time range.
The tool is read risk and uses the same tool-policy, case-scope and budget
gates. Pack installation, replacing a table or enlarging limits stay analyst
operations. Rule descriptions, original fields and match data are untrusted
through ContentGuard. Run status travels outside evidence text as typed tool
metadata. The model receives a bounded summary and existing local row
references.

## Proposed signed records and export

- `SigmaPackAdmissionV1` binds the approved pack digest and origin, versions
  and license metadata. `SigmaRunV1` binds the case checkpoint, scope/time,
  active Parquet inventory, exact pack/rule set, field table, evaluator
  version, reserved and used units and result status and digest.
- Match entries are stable by rule ID, rule hash and existing row order.
  Each carries the original evidence SHA-256 and record index, the signed
  event artifact SHA-256 and row locator, and any inherited incomplete-source
  notice. A run's findings are unconfirmed source findings. The analyst's
  existing confirmation gate is required to report one.
- Propose case marker 6 and export V10 shared with the report contract.
  Add an always-present count and bounded Sigma proof section with admitted
  rule objects, tables and result objects referenced by signed records. Keep
  the V9 capture semantics, the 1 MiB signed event limit and domain-separated
  commitments. Large result lists live in hashed object frames. Publish a
  run atomically with its receipts. Review the [shared V10 encoding and
  vectors](sigma-report-v10-wire.md) before implementation.
- Verify the signed checkpoint, all dependencies and result objects, and
  resolve each citation to the exact authenticated row. `/verify` distinguishes
  authenticating the receipt from rerunning an eligible scan with the same
  evaluator and data. Verification does not fetch a rule or execute external
  code. Prior-minor cases follow the existing creating-binary policy.

## Acceptance

Fuzz the bounded parser/compiler for 10 minutes with AddressSanitizer. Test
wrong types, duplicate and malicious fields, deep YAML, hostile rule metadata,
regex limits, modifier expansion, mismatch under negation, coverage failures,
bounded work, case scope and a compliant fake model trying to install a pack
or bypass it. Compare 1/N worker outputs and preserve_order builds, verify a
sealed export and reject tampered rules, references and partial flags.

Group rules by required columns and scope, push safe partition and row-group
predicates, and share bounded batch scans and literal matching. Preserve exact
rule semantics for every prefilter. Benchmark at least 2,000 synthetic rules
against 1 GiB of Parquet in release. Record compile time, scan time, bytes
read, rules evaluated or skipped, false positives on the known corpus and
peak memory. Measure both common-column and supported original-field paths.

The reviewed Rust `regex` dependency can be referenced directly when the
evaluator is implemented. The [YAML reader review](sigma-yaml-parser-review.md)
measures a separate candidate without changing the IRMind dependency graph.
The upstream archive importer needs separate dependency approval if the
bounded existing reader cannot be reused.
