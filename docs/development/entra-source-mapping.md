# Microsoft Entra source mapping

The experimental source module decodes four original export layouts: Azure
Monitor resource-log and Log Analytics object-row variants of sign-in and
directory audit logs. It preserves original field names, scalar types, precise
UTC time, provenance and dynamic JSON strings. Resource exports can be arrays,
NDJSON or a bounded `records` envelope. Graph API `value` wrappers and positional
Log Analytics query responses are not silently treated as object-row exports.

The source decoder selects formats and validates time; it does not interpret
outcome, role, MFA success or Conditional Access. A present invalid primary
timestamp rejects the record instead of falling back to a secondary timestamp.
Malformed or oversized records are counted with bounded untrusted samples;
subsequent valid records remain visible. Detection consumes only a separate
bounded sample. A 5, 50 and 200 MiB single-line envelope regression streams its
individual records without consuming the live reader during detection.

Four separately identified mappings bind bundled TOML definitions and a pure
native adapter in their release manifest. The adapter handles bounded Dynamic
JSON strings, target arrays, service-principal representations and explicit
status representations that finite scalar tables cannot express. It has no
I/O, clock or downloaded code. Encoded JSON must be exactly one value, at most
64 KiB, depth 32, 4,096 nodes and 1,024 fields. Target projection is capped at
16 members; coverage diagnostics accompany unsupported or conflicting values.
Original data remains available without promoting it to instructions.

Sign-in error code zero is success; a positive documented error code is failure.
Audit success/failure and timeout are explicit; absent/null, conflicting and
unrecognized values remain unknown. Conditional Access and MFA fields do not
supply the overall result. Authentication events use authentication/start;
directory audits use iam/info without guessing creation/change from free text.

Directory AADTenantId or resource tenantId supplies account scope. A Log
Analytics TenantId is a workspace and never substitutes for the directory.
Without directory scope, supported identities stay source-record scoped with a
coverage warning. User and service-principal actors remain distinct from audit
targets. Equal actor/target values retain both roles; source IP is independently
validated. No PID or process lifetime is invented.

The included Azure skill tests native sign-in and audit evidence through the
production decoder/mapping, guarded tool results, analyst confirmation,
verification, seal and public export. HuntEval expected answers remain in the
independent evaluator, outside evidence and model requests. A hostile-evidence
episode retains the existing policy ceiling and approval requirements.

## Primary references

- [Resource log export schema](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/resource-logs-schema).
- [Entra activity log schemas](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas).
- [SigninLogs fields and result codes](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs).
- [Service-principal sign-in fields](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs).
- [AuditLogs fields and result representations](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs).
