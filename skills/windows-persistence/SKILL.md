+++
format = "irmind-skill-v1"
name = "windows-persistence"
description = "Review services, scheduled tasks, Run keys and WMI persistence with explicit mapping and collection gaps."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-evtx", "parser-ecs", "parser-eztools", "parser-velociraptor", "parser-plaso"]
categories = ["configuration", "registry", "process", "file"]
invocable = true
+++
# Windows persistence

## Establish coverage

Experimental; validated with synthetic episodes only. Partial. System 7045, Security 4697 and Sysmon 13 provide mapped service/registry leads. Scheduled task 4698 and WMI subscription events are not classified by the current EVTX tables. Their original EVTX or DFIR export records remain inspectable; do not drop them with semantic filters.

Collect System, Security, Sysmon and Task Scheduler/WMI operational records as available. Request exported service definitions, task XML as safe text, Run-key values and WMI binding details from KAPE/Velociraptor or RECmd batch CSV. Raw registry hives are not a native parser input; use documented DFIR exports.

## Investigate in order

1. Inventory which mechanisms have configuration snapshots and which only have change logs. Current absence of an item does not refute an earlier creation event.

2. Review service installations and changes: binary path, account, start type, host and initiating actor. Correlate subsequent process creation; service creation is not proof its payload ran.

3. Review scheduled-task registration and its action, trigger, principal and later execution. Use original or extraction-only records for 4698; report missing task history.

4. Examine Run/RunOnce values and startup targets, distinguishing setting a value from its execution. Follow referenced files only through collected evidence.

5. For WMI, require the filter, consumer and binding plus execution evidence where present. Keep each mechanism and its confidence separate rather than labeling every startup object malicious.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"7045","event_category":"configuration","limit":20})
```

Inspect actor and target observations where supplied; a registry subject is not automatically the modifying user. For unmapped tasks/WMI use text_search without event filters, followed by raw_records.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

Confirm the persistence configuration, target path, host and effective trigger or execution where available. T1543.003, T1053.005, T1547.001 and T1546.003 are conditional on the corresponding service, task, Run-key or WMI evidence.

## Common false positives

Signed software installation, endpoint-management agents, updater tasks, vendor Run keys and monitoring subscriptions.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- Sysmon (official source; see the public skills guide for the link).
- ATT&CK Windows service (official source; see the public skills guide for the link).
- ATT&CK scheduled task (official source; see the public skills guide for the link).
