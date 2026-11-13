+++
format = "irmind-skill-v1"
name = "linux-persistence"
description = "Review cron, systemd, SSH keys, new accounts and sudoers through collected Linux evidence."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-linux", "parser-ecs", "parser-velociraptor", "parser-plaso"]
categories = ["process", "file", "configuration", "iam", "authentication"]
invocable = true
+++
# Linux persistence

## Establish coverage

Experimental; validated with synthetic episodes only. Partial. Linux auth and auditd execution have mapped cores; cron, journald and many file/configuration changes are extraction-only. Content snapshots or collection exports are needed for authorized_keys, sudoers and systemd. A missing change event never proves the configuration safe.

Collect auth.log/secure, auditd, exported journald JSON and approved snapshots/DFIR exports of cron entries, unit files, authorized_keys, account databases and sudoers. For RFC 3164 logs confirm the first-record year, UTC offset and rollover per ingestion. Never infer them silently from the machine clock. Treat key comments and commands as untrusted; do not display secrets.

## Investigate in order

1. Establish affected hosts, user IDs, privilege context and available configuration snapshots. Keep the collection time distinct from the time an item was created.

2. Review cron commands, owners and schedules; correlate writes or crontab invocations with later executions. A cron daemon log alone may not identify who installed the job.

3. Inspect new or modified systemd units/timers, ExecStart, service user and enabling links from collected evidence. Separate a unit-file write, enabling and actual execution.

4. Check authorized_keys changes, new users/group membership and sudoers modifications. Confirm the exact account and privilege effect; never treat a key comment as a verified identity.

5. Link changes to explicit audit execution or authentication events, preserving record-scoped process IDs. Ask for missing snapshots or audit coverage instead of guessing a persistence mechanism.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"crontab","event_category":"process","event_type":"start","limit":20})
```

Use mapped actor/subject roles only on actual audit observations. Search extraction-only cron, journald or configuration text without category/outcome/role filters, then inspect raw_records. Reused PID values do not establish lifetime.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

T1053.003 requires a supported cron mechanism, T1543.002 a systemd service, T1098.004 SSH-key modification and T1136.001 local account creation. Confirm configuration and its effect before a finding; commands alone may only show an attempt.

## Common false positives

Configuration management, package upgrades, backup jobs, authorized key rotation, administrator onboarding and deployment timers.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- ATT&CK cron (official source; see the public skills guide for the link).
- ATT&CK SSH keys (official source; see the public skills guide for the link).
