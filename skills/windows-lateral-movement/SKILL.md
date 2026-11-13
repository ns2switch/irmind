+++
format = "irmind-skill-v1"
name = "windows-lateral-movement"
description = "Correlate remote logons and execution over RDP, SMB, WMI and WinRM without inferring pass-the-hash."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-evtx", "parser-ecs", "parser-hayabusa", "parser-velociraptor"]
categories = ["authentication", "session", "process", "network", "configuration"]
invocable = true
+++
# Windows lateral movement

## Establish coverage

Experimental; validated with synthetic episodes only. Mapped core with partial protocol coverage. Security 4624/4625/4648/4688, System 7045 and Sysmon 1/3 are supported. WMI, WinRM and RDP operational details may remain extraction-only or require producer-normalized ECS. A type-3 logon alone is not proof of PsExec or pass-the-hash.

Collect source and destination Security/System/Sysmon logs and available RDP, WinRM and WMI operational exports within scope. Request account/domain IDs, logon IDs, source addresses and full service/process fields. KAPE or Velociraptor can collect these; IRMind analyzes their exports and does not execute remote commands.

## Investigate in order

1. Establish host and account namespaces and clock coverage on both ends. Start from successful and failed remote logons, preserving LogonType, authentication package and logon IDs from originals.

2. Correlate RDP type-10 or network type-3 events with actual session and process evidence. Explicit credentials 4648 can explain an initiating identity and target but do not prove credential theft.

3. For a PsExec hypothesis, require related service installation and destination execution, not just an administrative share connection. Examine 7045, 4688 and Sysmon 1/3 with their exact host and process identities.

4. For WMI or WinRM, require collected protocol or destination process evidence. Do not infer a protocol solely from a port, executable name or a co-observation edge.

5. Consider pass-the-hash only with independent credential/authentication evidence. Distinguish failed attempts, authorized remote administration and actual execution on the target.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"4624","event_category":"authentication","event_outcome":"success","limit":20})
```

Use source role for the remote address and actor/target for source and destination identities if mapped. Read LogonType and AuthenticationPackageName from raw_records. Keep record-scoped process identities separate from Sysmon ProcessGuid lifetimes.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

Confirm the two endpoints, identity, time, protocol evidence and target-side result. Use T1021.001 for evidenced RDP, T1021.002 for SMB/admin-share use, T1021.006 for WinRM and T1047 for WMI. T1550.002 needs evidence beyond a network logon.

## Common false positives

Help-desk tools, software deployment, vulnerability scanning, scheduled administration and management servers.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- Sysmon (official source; see the public skills guide for the link).
- ATT&CK remote services (official source; see the public skills guide for the link).
