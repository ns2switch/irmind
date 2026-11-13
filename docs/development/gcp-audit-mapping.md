# Cloud Audit and GKE source mapping

The experimental source module decodes original LogEntry fields and nanosecond
UTC time. It recognizes the Cloud Audit type and required service/method fields;
format decoding performs no network access and assigns no outcome or role.
GKE cluster labels are an untrusted identity claim. Acquisition confirmation,
per-record agreement and reconstruction use the existing signed cluster context.
A file cannot relabel non-cluster records with a GKE default; export those
resource types separately. At most eight explicit clusters can bind one source.

The ordinary cloud mapper is a bundled hash-pinned TOML table. Exact IAM and
IAM Credentials service names receive api/iam categorization. Storage, Compute
and GKE control-plane services have API coverage; documented Resource Manager
SetIamPolicy/GetIamPolicy names receive IAM coverage. Unsupported services or
methods remain unclassified. Explicit RPC status 0 is success, 1–16 is failure,
and absent/null status is unknown. Source severity and operation names do not
supply an outcome. Identity fields need an explicit project scope; missing or
provider-redacted identity remains a coverage limitation.

GKE uses the same finite status tables. Its native mapping wrapper validates
hierarchical Kubernetes resource names, namespace scope and regional versus
zonal locations, which the finite table language cannot express. Its build
manifest binds both those tables and the pure Rust validator. It does not infer
an original audit.k8s.io Event from Cloud Audit data. Unknown resource shapes
retain their source reference rather than fabricated pod/node identities.
Only validated common fields form the cluster search projection; full request
and response bodies remain originals. No code is downloaded during verification.

Original caller IP and optional destination IP are separate occurrences even
when equal. The literal provider redactions `private` and `gce-internal-ip` do
not become addresses. Reported principal and target resource stay distinct;
service-account delegation is retained in the original, without guessing the
human initiator. Kubernetes service-account principals use the existing closed
namespace/name grammar. PID-like request data never creates a process lifetime.

Contracts exercise precise time, missing/success/failure status, both endpoint
roles, namespaced GKE resources, source-label conflicts, later cluster
confirmation and 5/50/200 MiB first-line rejection. Integration tests use the
production catalog and verify ingest, typed queries, reconstruction, seal and
public export verification. Evaluator answers stay outside evidence/model input.

## Primary references

- [AuditLog fields and request metadata](https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog).
- [IAM audit methods](https://cloud.google.com/iam/docs/audit-logging).
- [IAM Credentials audit methods](https://cloud.google.com/iam/docs/audit-logging/audit-logging-iamcreds).
- [IAM policy history](https://cloud.google.com/iam/docs/review-iam-policy-history).
- [GKE resource and method filters](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging).
