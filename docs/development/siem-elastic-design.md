# Experimental Elasticsearch SIEM connector

This design is for connector authors and maintainers. It defines a read-only implementation of the existing `SiemPort` for self-managed Elasticsearch and Elastic Cloud data-plane endpoints. It adds no port, credential, product module or configuration entry by itself.

## API and permissions

Use the Elasticsearch search API for events and Elastic Security alerts. Elasticsearch documents `POST /{index}/_search` with API-key authentication and the index `read` privilege. Elastic recommends the `.alerts-security.alerts-<space-id>` alias for alerts, rather than internal rollover indices. The initial compatibility target is Elasticsearch 8.x and 9.x; synthetic contract responses are not a live-service validation.

| Capability | Request | Server-side constraints |
| --- | --- | --- |
| Event search | `POST /{configured-indices}/_search` | Exact approved account, UTC range, one compiled field comparison, bounded hits or aggregation |
| Alert retrieval | `POST /{configured-alert-alias}/_search` | Alert ID, exact approved account and UTC range; at most one matching alert |

The connector does not call Kibana management APIs, create API keys, update alerts, modify indices or submit scripts. A maintainer creates a data-plane API key with `read` only on the permitted event indices and the selected alert alias. Cluster administration, index writes and management API keys are unnecessary. The key is a new connector credential, not an existing Splunk or EDR credential.

Sources: [search API and its required privilege](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search), [alert index aliases and timestamps](https://www.elastic.co/docs/solutions/security/detect-and-alert/query-alert-indices), [index privileges](https://www.elastic.co/docs/reference/elasticsearch/security-privileges).

## Existing policy and query contract

Implement only `SiemPort::execute(&AuthorizedCall, &CancellationToken)`. Reject a different tool or configured source before any HTTP request. The application remains the sole dispatcher, policy authority, evidence writer and redaction boundary.

Compile the existing closed `SiemQuery`: `event_name`, `user`, `source_ip`, `host`; `eq`, `not_eq`, `prefix`; and events, count-by, top or distinct results. JSON serialization escapes values. No KQL, Lucene, ES|QL, scripts, arbitrary Query DSL or model-selected field names are accepted.

| IRMind field | Proposed ECS default |
| --- | --- |
| `event_name` | `event.action` |
| `user` | `user.name` |
| `source_ip` | `source.ip` |
| `host` | `host.name` |

The analyst configures the account field, timestamp field and any field-map overrides. These are validated identifiers. Every request adds the policy-authorized account and time interval as separate Boolean filters; no proposed comparison can remove them. The index patterns and alert alias come only from configuration. Reject unscoped wildcards, cross-cluster expressions and malformed patterns. A case or analyst approval cannot exceed the organization ceiling.

Keep the existing maximum 24-hour query interval and 20-result query limit. Event searches use bounded hits; aggregations use bounded buckets without returning event documents. Preserve provider metadata describing truncation, timeout, omitted buckets or approximation. A field/operator combination that cannot be translated safely fails explicitly before HTTP; it never falls back to a broader query or local aggregation of a truncated sample.

For alerts, use an exact ID filter within the configured alias and the same account/time constraints. The timestamp field defaults to `@timestamp`, which Elastic documents as the alert creation time. An analyst can explicitly select a supported original-event timestamp field if their deployment requires that interpretation.

## Configuration and credentials

The proposed module is `siem-elastic`, with Cargo feature `siem-elastic`. Like other product modules it is compiled by default and remains disabled until configured. Show it as experimental in Settings and the English/Spanish module guides.

Non-secret settings cover the HTTPS origin, source ID, allowed index patterns, alert alias, account/time fields, optional field mappings and optional connector CA path/fingerprint. Settings changes use the existing signed configuration and egress confirmations.

The proposed secret field is `IRMIND_ELASTIC_API_KEY`. The composition root reads it through the configured `SecretBackend` and injects it. The connector never reads the environment, a credential file or a keystore itself. Mark the `Authorization: ApiKey` header sensitive. Keep credential values out of `Debug`, errors, tracing, case context and evidence. An authentication failure reports a fixed reason or HTTP status, not the response body or URL.

Use the existing shared HTTP utility: HTTPS with native roots plus the optional pinned connector CA, hostname verification, no redirects, cancellation, a finite timeout and a 5 MB response ceiling. The proposed external dependencies already exist in the workspace: `reqwest`, `serde_json`, `secrecy` and `chrono`. No JWT library or new lockfile package is required for Elastic.

## Acceptance

- Shared SIEM contracts with positive synthetic event, aggregation and alert responses.
- Wrong source/tool, malformed fields/patterns, unsupported comparisons and excessive windows fail before HTTP.
- Every generated request retains configured indices, approved account, UTC filters and result bounds.
- Cancellation, timeout, response-size rejection and no-redirect contracts pass.
- Custom-CA success, missing-CA failure and hostname mismatch failure pass using the existing TLS test server.
- A signed approval dispatches through the existing registry, stores full evidence and sends only guarded/redacted context to a fake model.
- Configuration/key handling produces no credential in errors or debug output.
- English and Spanish setup guides document minimum privileges, field mappings, limitations and synthetic-only validation.

The implementation retains existing policy, signed formats and disabled-by-default remote services. This document does not implement credential loading or request execution.
