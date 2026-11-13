+++
format = "irmind-skill-v1"
name = "azure-entra-identity-compromise"
description = "Review Entra sign-ins, MFA and OAuth changes, role grants and application credentials with explicit coverage gaps."
version = "0.1.1"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-entra", "parser-ecs", "parser-json"]
categories = ["authentication", "iam", "configuration"]
invocable = true
+++
# Azure Entra identity compromise

## Establish coverage

Experimental; validated with synthetic episodes only. Native Microsoft Entra sign-in and directory audit exports are decoded by parser-entra and mapped by mapping-entra. Azure Monitor resource-log JSON (including a records envelope) and Log Analytics object rows cover interactive, non-interactive, service-principal and managed-identity sign-ins, plus AuditLogs. Producer-normalized ECS and configured Chronicle UDM remain alternatives. Azure Activity and arbitrary portal/Graph response wrappers need a supported conversion; do not assume they share the Entra layout.

Explicit sign-in status codes and directory audit result values supply outcome. Conditional Access and MFA details remain original evidence; their presence is not proof that MFA succeeded. Dynamic TargetResources and InitiatedBy JSON strings are decoded with strict bounds for mapping and retained unchanged in the original record. Distinguish the directory AADTenantId from a Log Analytics workspace TenantId.

Ask the analyst to download sign-in and audit logs as JSON from Entra Monitoring & health and export Azure Activity for the authorized tenant, subscriptions and UTC window. Reports Reader is the documented least role for the portal log download; access, licensing and retention vary. Collect applied authentication details, Conditional Access results, initiatedBy, targetResources, modifiedProperties, app/service-principal IDs and correlation IDs. If using ECS or UDM, retain the native identifiers and original results alongside the producer mapping.

## Investigate in order

1. Inventory tenant, user and application namespaces and actual sign-in/audit coverage. Distinguish a user login from a service-principal or managed-identity login. Missing risk fields do not mean a safe login.

2. Inspect suspicious sign-ins by original address, client, authentication requirement/result, device and session. A failed MFA challenge, failed Conditional Access or interrupted login is not a successful account takeover.

3. Follow MFA method registration/removal and authentication-policy changes. Confirm the initiating identity and changed target from the original audit details, rather than matching only display names.

4. Review directory-role assignments and OAuth consent, grants and application/service-principal credential additions. Preserve appId versus objectId, permission scopes, grant type, initiating principal and target separately.

5. Correlate suspicious authentication with credential/role changes and later resource access. Treat geolocation, unfamiliar IPs and provider risk alerts as leads; request missing logs instead of inventing a sequence.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"login","event_category":"authentication","event_outcome":"failure","limit":20})
```

This query applies to native Entra and explicitly mapped ECS/UDM records with matching original action text. Use entity_role="actor" or "target" only when that observation exists. Authentication and directory IAM events with an absent or contradictory status have outcome unknown. For unmapped generic JSON use original activity names and raw_records without semantic filters.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

Confirm the identity IDs, actual authentication outcome and the exact changed role, MFA method, grant or credential. Separate attempted misuse from an effective change. T1078.004, T1098.001 and T1098.003 are hypotheses only when their corresponding cloud-account use, added credential or role grant is evidenced.

## Common false positives

Travel, VPN egress, automation, help-desk MFA resets, approved privileged-identity activation, consent administration and planned secret rotation.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- Download Entra logs (official source; see the public skills guide for the link).
- Audit activities (official source; see the public skills guide for the link).
- ATT&CK additional cloud credentials (official source; see the public skills guide for the link).
