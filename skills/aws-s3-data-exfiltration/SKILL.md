+++
format = "irmind-skill-v1"
name = "aws-s3-data-exfiltration"
description = "Review S3 exposure, permission changes and unusual object reads without equating access with exfiltration."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-json"]
categories = ["api", "file", "configuration", "iam"]
invocable = true
+++
# AWS S3 data exfiltration

## Establish coverage

Experimental; validated with synthetic episodes only. Partial. CloudTrail GetObject/PutObject/DeleteObject have mapped API semantics. Bucket policy, ACL, public-access changes and data-event details remain searchable original fields; not every S3 operation has a semantic rule.

Ask the analyst to export CloudTrail management events and the relevant S3 object data events for the authorized buckets, accounts, regions and window. Object data events are not enabled by default and are not in the ordinary event-history view. Preserve eventID, requestParameters, resources, userIdentity, sourceIPAddress, userAgent, errorCode and additionalEventData. No remote collection is performed by this skill.

## Investigate in order

1. Establish which buckets, prefixes and periods actually have read data events. Use graph_summary and inspect a raw record before selecting filters. Record missing data-event coverage explicitly.

2. Review PutBucketPolicy, PutBucketAcl, PutObjectAcl and public-access-block changes by exact original eventName. Separate the actor, resource owner, granted principal and affected prefix. Verify the effective policy or ACL with collected evidence; a change event alone does not prove public reachability.

3. Compare GetObject activity with the identity baseline: source addresses, user agent, sessions, bucket/prefix, time and observed request volume. Use bounded timeline pages; a sampled page is not a whole-case count.

4. Correlate new permission grants with subsequent successful reads. Inspect response/error fields and any recorded transfer bytes. Preserve failed attempts and alternate backup or replication explanations.

5. Check whether the collected evidence supports unauthorized reading, staging or an actual transfer outside the approved boundary. State precisely which of these is established. Never claim exfiltration volume from request counts alone.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"GetObject","event_category":"api","event_type":"access","event_outcome":"success","limit":20})
```

For mapped reads, entity_timeline on the source IP may use entity_role="source"; inspect the namespace before following the actor. For unmapped policy changes omit semantic and role filters and review raw_records.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

Before proposing data theft, confirm the specific objects or prefix, actor/session, authorization context and successful reads. Cite source hash and record index for every permission or read claim. Propose T1530 for observed cloud collection; T1567.002 requires separate evidence of exfiltration to cloud storage, not merely GetObject.

## Common false positives

Backups, analytics, CDN origin reads, incident-response exports, replication, approved policy rollouts and NAT changes can resemble bulk access.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- S3 CloudTrail events (official source; see the public skills guide for the link).
- Object data events (official source; see the public skills guide for the link).
- ATT&CK T1530 (official source; see the public skills guide for the link).
