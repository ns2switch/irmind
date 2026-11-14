# Forensic skills

This page is for analysts who want a repeatable investigation method without granting the agent more permissions. A skill is a small, versioned folder of methodology and reference data. It contains no executable code.

## Use an included method

Open a case, configure a model in `/settings model`, and type `/` to see the active methods. The binary includes 15 methods. All are experimental and tested with synthetic episodes, not validated forensic conclusions.

| Command | Purpose | Required sources | Coverage |
| --- | --- | --- | --- |
| `/windows-triage` | Windows logons, execution and follow-on activity. | EVTX or Hayabusa, EZTools, Velociraptor/plaso exports. | Partial: depends on collected channels and exported artifacts. |
| `/linux-triage` | Authentication, privilege changes and execution. | auth.log/secure, auditd, journald. | Mapped authentication/execution core; other activity may be extraction-only. |
| `/aws-credential-compromise` | Credential use and privilege changes. | CloudTrail management events. | Mapped operations only; missing data events constrain follow-on analysis. |
| `/aws-s3-data-exfiltration` | S3 exposure, permissions and unusual reads. | CloudTrail management **and S3 data events**. | Partial: mapped GetObject uses `api/access`; policy/ACL details require original fields. |
| `/azure-entra-identity-compromise` | Sign-ins, MFA, roles, OAuth consent and application credentials. | Native Azure Monitor SignInLogs/AuditLogs or Log Analytics object rows; optional ECS/UDM. | Native outcome and role mapping; original MFA and Conditional Access details. Collection does not prove complete tenant coverage. |
| `/gcp-service-account-abuse` | Keys, impersonation and IAM changes. | Cloud Audit Logs JSON; optional producer-normalized ECS. | Typed IAM/IAM Credentials and documented project-policy operations; missing status/identity and unsupported services remain coverage gaps. |
| `/windows-ransomware` | Recovery inhibition, propagation and possible file impact. | EVTX/Sysmon plus collected file/recovery/defender observations. | Partial: command attempts alone do not establish encryption or successful defense changes. |
| `/windows-lateral-movement` | RDP, SMB/PsExec, WMI, WinRM and credential-use leads. | Source/destination Security, System, Sysmon and operational logs. | Mapped logon/service core; type-3 logon alone never proves pass-the-hash. |
| `/windows-persistence` | Services, tasks, Run keys and WMI subscriptions. | EVTX and collected configuration/DFIR exports. | Partial: task 4698 and WMI subscriptions lack current semantic table rules. |
| `/linux-webshell` | Web requests correlated with web-user execution. | nginx/Apache common/combined and auditd; collected web-root evidence. | Mapped HTTP/execve core; host, request ID or causal linkage may be missing. |
| `/linux-persistence` | Cron, systemd, SSH keys, accounts and sudoers. | Linux logs plus collected configuration or DFIR exports. | Partial: sparse logs do not reconstruct complete configuration state. |
| `/network-c2-beaconing` | Periodic flows, suspicious DNS and alerts. | Zeek and Suricata EVE; optional producer-normalized ECS. | Mapped protocol categories and source/destination roles; missing status stays unknown. Source alerts remain unconfirmed. |
| `/malware-execution-triage` | Binary origin, execution and observed follow-on activity. | Sysmon 1/3/11 and PECmd/AmcacheParser or other DFIR exports. | Partial: Amcache presence is not proof of execution; raw binary artifacts need an export. |
| `/k8s-cluster-compromise` | API access, secret-read attempts, service accounts and RBAC changes. | Native/EKS/AKS Kubernetes audit Events, GKE Cloud Audit exports; optional Falco k8s_audit. | Mapped API outcomes and cluster-scoped identities; binding contents require verified originals. Effective RBAC state and omitted audit bodies remain gaps. |
| `/k8s-workload-compromise` | Risky pod requests, exec/attach leads and runtime correlation. | Kubernetes audit plus Falco JSON with pod/container metadata. | Original pod specs and mapped runtime observations; an accepted request or privilege flag alone does not prove execution, escape or cryptomining. |

See the [parser guide](parsers.md) and [module configuration](modules.md) before collecting data. Skills declare only the local tools needed by their methodology. None runs a collector, accesses a provider, installs a mapper or expands case scope.

### Collect enough evidence

Each method has a coverage section and a small reference table. It explains which sources and mappings are required, how an analyst can obtain them, and what remains unknown. Windows collection uses approved KAPE or Velociraptor procedures and exports from tools such as EZTools; IRMind does not parse every binary artifact directly. Cloud logs need the relevant audit types and retention window, not just a connector configuration.

Use `graph_summary` and inspect original records before applying common-schema filters. Typed `event_category`, `event_type`, `event_outcome` and `entity_role` filters return only matching mapped coverage. They can exclude unclassified records. For extraction-only sources, use bounded text search, entity timelines where entities actually exist, and original records. No skill may fill a missing role or outcome by guessing. Ask the analyst for missing evidence and record the limitation.

The methods include common false positives and conditions for an ATT&CK proposal. Similar timing, a graph edge, an alert or a command line is not automatically a confirmed attack. Only the analyst confirms findings.

You can append a question, for example `/linux-triage Review the failed logins in this case.` The agent can also select a method from its description. No model or remote connector is enabled by a skill. You can inspect all methods without configuring a model.

The model initially receives only active names and descriptions. When it requests `skill_read`, IRMind checks policy, pins the approved package in the case, screens its requested resource and signs a load receipt with the Agent key before exposing the text. The conversation shows a collapsible methodology card. Use Ctrl+O or `/expand` for its details.


## Inspect original source facts

`raw_records` reads the indexed projection by default. A method needing a role binding's `roleRef`/subjects or a pod's requested security settings explicitly uses `view="original"`. The original view authenticates the signed source bytes and reproduces its entire decoded-record commitment with the recorded decoder and acquisition context before returning a guarded excerpt. It does not flatten the original bodies into search or contact a cloud provider.

Successful local ingestion authorizes that selected source directory for the current session. After reopening a case, select the originals explicitly with `/verify <source-root>`; only checked sources are authorized. Changing cases clears the previous local directory authorizations. Private originals explicitly copied into the case need no external directory. A missing source, unavailable decoder, changed hash, absent authorization or deadline produces an unavailable result, never a projection presented as an original.

The existing 10-second deadline, pointer limit and 2,000-character excerpt remain. A very large source may not decode within the deadline; truncated excerpts and missing bodies are coverage gaps. Privacy redaction and the guard still apply to identifiers and text. Do not infer missing fields from a projection or from an excerpt that omits them. [The read contract](development/verified-original-record-read.md) describes the bounds.

For Kubernetes, collect authorized API-server audit logs with an audit policy that records the needed metadata or bodies. Enable/export control-plane audit logs for EKS, Kubernetes Cloud Audit entries for GKE, or kube-audit/kube-audit-admin diagnostics for AKS as described in the [parser guide](parsers.md). IRMind performs no collection and implements no live Kubernetes API connector. Falco `source="k8s_audit"` and syscall alerts have separate mappings; source alerts remain unconfirmed, and the collection cluster must be explicitly confirmed. Cloud-to-cluster identity links must exist in the collected evidence; a service-account or pod name alone is not a link.

## Manage local packages

Use `/skills` from the home screen or a case. Choose a method with the arrows. Tab selects an action; Enter opens it. Typing an option number followed by Enter also works.

1. **Inspect** shows the version, package hash, declared tools and resources.
2. **Install/update** opens a folder field. Select a local folder with `SKILL.md`, inspect the exact preview and sign the installation or replacement.
3. **Enable/disable** signs the activation change. Disabling prevents future loads; it does not remove earlier case receipts.
4. **Restore approved file** explicitly restores an installed package from its signed installation record after local files were removed or changed.

Esc returns without applying a preview. Installation, updates and activation changes use the Analyst key and the signed global operation chain. Modified, missing or unsupported installed packages stay unavailable; IRMind never silently substitutes an included method. The demo permits inspection but does not change your real skill installations.

Download community packages explicitly and verify their published hashes before inspecting and signing them. IRMind does not fetch packages automatically. A signature records your approval of exact bytes; it does not make their claims correct or their instructions trusted.

## Limits and security

A package contains `SKILL.md` plus at most 16 resources, with a total limit of 128 KiB and 32 KiB per resource. At most 32 methods can be active. One model turn can load at most four distinct snapshots and eight resources, with at most 64 KiB of screened methodology and any smaller context/token limit. A limit produces a signed result; content is not silently truncated.

Skill text is always untrusted. It never enters a system message, never becomes evidence and cannot be cited as an evidence hash. Declared tools restrict method-assisted calls; normal policy, case scope, organization ceilings, taint checks, approvals and budgets still apply. A skill cannot confirm its own findings. Missing semantic mappings mean incomplete coverage, not permission to invent classification.

The signed case preserves the original package and the screened ranges actually loaded. Export V7 carries the exact referenced installation proofs for independent verification without your keystore. It authenticates recorded methodology use; it does not claim to reproduce a model response or establish the quality of a forensic conclusion.

Pre-1.0 minor versions may change skill and export formats without migration. Keep the version that created a case. See the [security model](security-model.md), [installation configuration](configuration.md) and [development design](development/skills-design.md).

## Methodology references

The methods use original project-licensed prose. Their public sources include
[AWS S3 audit logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html),
[S3 data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-s3-data-events-governance.html),
[Entra log export](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-download-logs),
[Entra audit activities](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities),
[GCP IAM audit logging](https://docs.cloud.google.com/iam/docs/audit-logging),
[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[Zeek connections](https://docs.zeek.org/en/current/logs/conn.html),
[Suricata EVE](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
and [MITRE ATT&CK](https://attack.mitre.org/). Links live here rather than in
loaded methodology: skill content passes the same guard as other untrusted text.

Kubernetes methods reference [auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) and [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), the [Falco Kubernetes audit plugin field contract](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/README.md), and ATT&CK [additional container cluster roles](https://attack.mitre.org/techniques/T1098/006/), [container API credential access](https://attack.mitre.org/techniques/T1552/007/), [deployment](https://attack.mitre.org/techniques/T1610/), [administration](https://attack.mitre.org/techniques/T1609/) and [escape to host](https://attack.mitre.org/techniques/T1611/). The methodology is original project text; these references do not establish a finding.
