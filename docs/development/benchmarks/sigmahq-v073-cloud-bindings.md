# SigmaHQ audit of the expanded cloud and macOS bindings

The release-profile V3 compiler checked the same 3,302 files from the
[hash-pinned SigmaHQ audit](sigmahq-v070-admission.md) with no evidence.
The compiler ran once per file, in a separate process with 512 MiB of
address space and two seconds each of CPU time and wall time. Each row
uses the cumulative table after installing that family of bindings.
All five runs admitted 3,301 files, with no panics or process-limit
terminations. The results measure compilation for source classes.
They do not measure detection on case data.

| Table snapshot / Tabla acumulada | Azure / 123 | GCP / 25 | Kubernetes / 9 | M365 / 18 | macOS / 52 | Eligible pairs / Pares aptos, all families |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| #433 baseline / Referencia | 1 | 0 | 1 | 2 | 1 | 4,555 |
| Azure | 63 | 0 | 1 | 2 | 1 | 4,628 |
| GCP | 63 | 13 | 1 | 2 | 1 | 4,641 |
| Kubernetes | 63 | 13 | 8 | 2 | 1 | 4,662 |
| M365 | 63 | 13 | 8 | 4 | 1 | 4,664 |
| macOS | 63 | 13 | 8 | 4 | 3 | 4,666 |

The family columns count distinct rules with at least one eligible
class. The combined table compiles 2,221 rules for at least one class,
including 1,221 for every applicable class. The original table compiled
2,135 for at least one class. The table retains 5,668 missing-binding
pairs and 72 incompatible-type pairs.

## Exact bindings and remaining gaps

- Azure uses separate selectors for Log Analytics table rows and diagnostic
  resource envelopes. It reads exact scalar fields such as the operation
  name, service, caller fields and sign-in status details. The original
  `properties.message` text is read only from the diagnostic envelope,
  or the corresponding `Properties_d.message` leaf in AzureActivity.
  The interpreter does not parse JSON strings as objects. It does not
  stringify structured sign-in `Status` or reinterpret the string
  `ResultType` as an integer. PIM and risk detection remain separate
  log sources.
  [Sign-in table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs) · [Audit table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/auditlogs) · [Activity table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azureactivity) · [Activity log schema](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log-schema).
- `gcp.audit.method_name` binds exactly to the original
  `protoPayload.methodName`. The reviewed correlation namespace aliases
  for service and method use the same original record. The table does
  not zip or flatten entries from `authorizationInfo`, and it does
  not cover Google Workspace log sources.
  [Cloud Audit Logs](https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs).
- Native Kubernetes, EKS and AKS qualify their audit API events for the
  `application` category. They use the native `objectRef` API group,
  subresource and name, request URI, user agent and user groups. GKE
  keeps its own `protoPayload` bindings and does not infer an original
  Kubernetes verb from its method name. The existing provenance and
  explicit exact-field unavailability rules still apply.
  [Kubernetes audit API](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/) · [GKE audit logging](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/audit-logging).
- M365 reads exact retained `ApplicationId`, `RequestType`, `DeliveryAction`
  and `Directionality` values when supplied. It keeps the existing
  Exchange workload selector. It does not enroll separate threat
  management or threat detection logs.
  [Microsoft 365 audit schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema).
- macOS file creation uses the event process executable for `Image`.
  Execution retains its argument array as `Arguments`. An argument
  array does not supply the original command-line string. The parent
  audit token and PID do not supply a parent executable path.
  [Endpoint Security exec](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t) · [Endpoint Security process](https://developer.apple.com/documentation/endpointsecurity/es_process_t).

Las cifras indican cuántas reglas compilan para al menos una clase.
Las rutas nuevas leen claves de objetos exactas y no recorren listas
de objetos. Los campos ausentes o que requieren una representación
distinta siguen siendo límites de cobertura por clase.
