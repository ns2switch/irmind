+++
format = "irmind-skill-v1"
name = "network-c2-beaconing"
description = "Review periodic connections, DNS and network alerts without treating regular traffic as proof of C2."
version = "0.1.1"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-zeek", "parser-suricata", "parser-ecs"]
categories = ["network", "intrusion_detection"]
invocable = true
+++
# Network C2 beaconing

## Establish coverage

Experimental; validated with synthetic episodes only. Native Zeek and Suricata mappings provide network/protocol categories, explicit source/destination roles and outcomes only when the source reports a supported status. Missing status stays unknown; an observed flow or an allowed alert is not proof of success or compromise. UID/flow_id correlations and original fields remain available. The common schema has one DNS-question slot: additional questions remain original evidence with an explicit coverage diagnostic. Interval statistics must be based on the actual bounded records, not invented whole-case aggregates.

Ask the analyst for Zeek logs with headers or JSON, relevant Suricata EVE JSON, sensor timezone/configuration and the authorized time window. Collect conn, dns and available http/ssl/tls plus alert records; retain uid/flow_id. No packet capture or live network probing is performed by this skill.

## Investigate in order

1. Establish sensor locations, NAT/proxy visibility, missing log types and time coverage. Distinguish a source endpoint from a sensor observer and keep provider namespaces.

2. Review repeated connections to the same destination and the actual ordered timestamps, durations and byte counts. State the sample size and interval window. A bounded timeline cannot prove a case-wide periodicity rate.

3. Correlate uid or flow_id with DNS, TLS/HTTP and alerts where the identifiers are present. Inspect original query names, answers, SNI and protocol fields; a graph edge alone is not the same flow.

4. Compare timing regularity, failures, asymmetric transfer and new destinations against expected updates, monitoring and scheduled services. DNS repetition or an alert signature is supporting context, not proof of malware.

5. Propose suspicious beaconing only with cited observations and an explained alternative baseline. Do not resolve or contact domains, send probes or query external intelligence through this local-only method.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"203.0.113.77","limit":20,"event_category":"network","event_type":"connection","event_outcome":"unknown","entity_role":"destination"})
```

Use entity_timeline with kind="ip", event_category="network", event_type="connection" and entity_role="destination" for bounded flow review. Select the actual outcome (including unknown); success must not be assumed for an observed flow. DNS, HTTP and TLS use protocol events, with HTTP also categorized as web. Source alerts are unconfirmed intrusion_detection events and need separate queries. Inspect coverage diagnostics and originals before excluding records with typed filters.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

Cite interval timestamps and linked DNS/flow/alert records, including limitations and benign comparators. T1071.001 or T1071.004 requires supported web or DNS application-layer C2 evidence; periodic connections alone remain a hypothesis, not confirmed command and control.

## Common false positives

Software updates, telemetry agents, NTP, health checks, backup schedules, browser background traffic and retry storms.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- Zeek connection log (official source; see the public skills guide for the link).
- Suricata EVE format (official source; see the public skills guide for the link).
- ATT&CK application layer protocol (official source; see the public skills guide for the link).
