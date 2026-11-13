+++
format = "irmind-skill-v1"
name = "gcp-service-account-abuse"
description = "Review service-account keys, impersonation, IAM changes and unfamiliar use in Cloud Audit Logs."
version = "0.1.1"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-gcp-audit", "parser-ecs"]
categories = ["iam", "authentication", "api"]
invocable = true
+++
# GCP service account abuse

## Establish coverage

Experimental; validated with synthetic episodes only. Native Cloud Audit LogEntry JSON/NDJSON uses parser-gcp-audit and bundled service/status tables. IAM and IAM Credentials operations have api/iam categories; documented project SetIamPolicy/GetIamPolicy operations have the same typed coverage. Explicit RPC code 0 means success, 1–16 means failure, and missing status stays unknown. Reported callers, resources and endpoints retain distinct roles. Other services or missing/redacted identity fields can leave coverage incomplete; inspect graph_summary before a negative conclusion. HuntEval normalized data still tests extraction separately.

Ask the analyst for Cloud Logging JSON exports covering Admin Activity and any relevant Data Access logs for the authorized projects and UTC window. Retain protoPayload.serviceName, methodName, authenticationInfo, serviceAccountDelegationInfo, authorizationInfo, requestMetadata, status and resourceName. Data Access and credential/token-use visibility depend on enabled audit coverage; do not assume all calls were logged.

## Investigate in order

1. Identify project, service-account email and immutable identity IDs where supplied. Keep human initiator, service account and impersonated target distinct. Inventory enabled audit log types before a negative conclusion.

2. Search original CreateServiceAccountKey activity and inspect response/status, key ID and the target account. Do not request or display private key material. Compare with approved rotation evidence.

3. Examine IAM Credentials token issuance and serviceAccountDelegationInfo. Preserve the whole delegation chain and the requested target; seeing the service account in a resource name does not prove who used it.

4. Review SetIamPolicy operations and their actual bindings/deltas, including service-account-user or token-creator grants. A request body alone is not proof of an effective successful policy update.

5. Follow subsequent calls by the account and compare caller IP, user agent, project and service with the observed baseline. Use raw status semantics: an absent status must not be guessed into a typed outcome by this skill.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"CreateServiceAccountKey","event_category":"iam","event_outcome":"success","entity_role":"actor","limit":20})
```

For supported native GCP use event_category="iam", event_type="access", event_outcome and entity_role filters. An API access type does not establish that a proposed policy change took effect. Read original authenticationInfo, serviceAccountDelegationInfo, authorizationInfo and resourceName with raw_records; a reported caller is not necessarily the human initiator behind delegation. Private/redacted caller IP labels are not IP entities. Do not use typed filters to hide unclassified services or claim collection completeness.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

Confirm key creation, explicit delegation or effective role grant with original fields and status. Cite hashes and record indices. T1098.001 covers evidenced additional cloud credentials; T1098.003 covers actual role additions. Account use or a new source alone does not prove a stolen key.

## Common false positives

Workload identity, token delegation by build systems, service-account rotation, administrator automation, NAT or region changes and legitimate cross-project service access.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- IAM audit logging (official source; see the public skills guide for the link).
- ATT&CK additional cloud credentials (official source; see the public skills guide for the link).
