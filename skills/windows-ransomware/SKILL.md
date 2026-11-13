+++
format = "irmind-skill-v1"
name = "windows-ransomware"
description = "Correlate Windows access, execution, recovery inhibition and file impact before proposing ransomware."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-evtx", "parser-ecs", "parser-eztools", "parser-velociraptor", "parser-plaso"]
categories = ["authentication", "process", "file", "registry"]
invocable = true
+++
# Windows ransomware

## Establish coverage

Experimental; validated with synthetic episodes only. Partial. Mapped EVTX covers Security logons/execution, System services, PowerShell 4103/4104 and Sysmon 1/3/11/13/22. Defender changes, shadow-copy state and file encryption require supporting collected records or exported artifacts. IRMind does not infer encryption from a rename or ransom-note filename.

Ask the analyst to collect Security, System, PowerShell Operational and available Sysmon EVTX using an approved collector such as KAPE or Velociraptor. Include hashes and acquisition provenance for exported file metadata, ransom notes and any recovery/defender telemetry. Feed EZTools CSV, Velociraptor JSON or plaso JSONL rather than raw registry, MFT or Prefetch binaries. Do not run suspicious binaries or delete recovery copies.

## Investigate in order

1. Establish the earliest supported access and host/user timeline. Distinguish an initial-access observation from the first event retained in a limited log window.

2. Follow process creation and network events into remote execution or lateral movement. Use documented ProcessGuid relationships when present; PID reuse and shared accounts must not join unrelated lifetimes.

3. Inspect explicit defense-control and recovery-inhibition commands in PowerShell or process records. A command launch proves an attempt; confirm its result using output, follow-on state or additional logs.

4. Correlate bursts of file changes and candidate ransom-note creation with the same host/process and time window. Review collected file evidence or content observations to distinguish encryption from compression, backup or renaming.

5. Build a bounded sequence of access, propagation, defense interference and impact. Mark absent stages as unobserved. Never execute the sample or containment as part of this method.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"vssadmin","event_category":"process","event_type":"start","limit":20})
```

Use actor for the initiating user and subject for the mapped process only when supplied. Review raw event IDs and command lines for unknown categories. Do not infer a process lifetime from PID or timestamp.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

Propose T1490 only for supported recovery inhibition; T1486 requires evidence of encryption impact, not merely a suspicious program name. Each stage needs source hashes, record references and alternate explanations. The analyst confirms findings.

## Common false positives

Backup agents, restore-point maintenance, installers, bulk file migrations, sanctioned encryption and simulation exercises.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- Sysmon event coverage (official source; see the public skills guide for the link).
- ATT&CK encryption impact (official source; see the public skills guide for the link).
- ATT&CK recovery inhibition (official source; see the public skills guide for the link).
