# Managed Kubernetes audit transports

The Kubernetes source module adds two explicit transport formats under its
existing decoder port. Native audit.k8s.io/v1 Events retain their original
fields and source version. EKS GetLogEvents rows and AKS diagnostic rows retain
both the typed original `transport` and the decoded `audit_event`; bounded JSON
unescaping is format decoding, not classification. Event time comes from the
original stageTimestamp/requestReceivedTimestamp. An outer delivery timestamp
never becomes an invented event instant. Provenance points to the actual outer
JSON row, not an invented byte position within an escaped message. The original
member ordinal remains in the source annotation when earlier rows are rejected.

EKS accepts GetLogEvents `events` arrays or individual object rows containing a
numeric timestamp and a message with a native audit Event. Acquisition requires
an explicit EKS cluster ARN. A log-stream name or current AWS profile is not a
cluster identity. IRMind neither discovers AWS credentials nor runs the AWS CLI.
CloudWatch subscription base64/compressed envelopes are not this source format.

AKS accepts kube-audit and kube-audit-admin diagnostic resource rows with
properties.log, including the standard records envelope. AzureDiagnostics
object rows with Category/log_s are also accepted. Original resourceId,
ResourceId or _ResourceId values are explicit source claims: present aliases
must agree exactly and identify an AKS managed cluster. Each claim is confirmed
by the analyst and bound to the source's signed context. Missing claims need an
explicit analyst/command identity. A new later claim requires confirmation of
the enlarged bounded set; contradictory manually supplied identity fails.
Positional query API tables and the different AKSAudit table schema are not
silently converted to native Events.

GKE keeps its independent Cloud Audit LogEntry decoder/mapping. Its bounded
sample detector now frames the first original record in gcloud JSON arrays as
well as NDJSON. Its decoded output, cluster-label rules and mapping are unchanged.

The EKS and AKS table modules are separate bundled canonical commitments. Their
selectors are disjoint; field paths have an explicit audit_event prefix. They
use the same documented HTTP status rules, actor/impersonation roles and target
resource type checks as the native tables. They never classify transport success
as API success. Full request/response bodies remain original evidence rather
than searchable instructions or an automatic flat projection.

The existing record-size/depth/field/node limits apply to the complete decoded
representation, including retained transport fields. Invalid embedded records
are counted with bounded untrusted samples and do not hide the next valid row.
Cluster conflicts stop the source for explicit confirmation/rollback; they do
not publish a partially relabeled source. Cancel, transaction, source hash,
reconstruction, partition assignment and export verification retain their
existing contracts. No new abstract port, dependency or credential is needed.

## Primary references

- [Kubernetes audit Event schema](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/).
- [Kubernetes auditing and log backend](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).
- [EKS control-plane audit logging](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html).
- [GetLogEvents original response fields](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetLogEvents.html).
- [Azure Monitor resource log export schema](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/resource-logs-schema).
- [AKS monitoring and log categories](https://learn.microsoft.com/en-us/azure/aks/monitor-aks).
- [GKE audit log exports](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging).
