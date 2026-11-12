+++
format = "irmind-skill-v1"
name = "windows-triage"
description = "Review Windows sign-ins, execution, persistence and lateral activity from collected logs."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_lookup", "entity_timeline", "neighbors", "path", "raw_records", "case_add_finding"]
sources = ["parser-evtx", "parser-hayabusa", "parser-eztools", "parser-velociraptor", "parser-plaso"]
categories = ["authentication", "process", "configuration", "file", "network", "registry"]
invocable = true
+++
# Windows triage

## Establish coverage

Start with the case scope and indexed-source summary. Check which hosts, channels
and intervals were collected. Ask the analyst to collect missing artifacts with
an approved collection workflow; this method does not run a collector. KAPE or
Velociraptor collections may contain both original artifacts and exported tables.

Read EVTX or a Hayabusa timeline first. Follow relevant execution and persistence
leads in EZTools exports: PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd,
LECmd, RECmd and SrumECmd. Treat collection times, parser timestamps and event
times as different observations. Missing logs do not establish absence of activity.

## Investigate in order

1. Review successful and failed sign-ins. Keep the actor, target user, source IP,
   logon type, account namespace and host separate. Compare nearby events rather
   than assuming that a failed sign-in was followed by compromise.
2. Trace execution using process creation records and supporting artifacts.
   A PID is not a lifetime identifier. Scope observations to their source record;
   correlate a Sysmon ProcessGuid only when it is present in the original record.
3. Examine new services, scheduled tasks, account changes, registry writes and
   PowerShell observations for persistence. Inspect the bounded original record
   before interpreting an exported detection label.
4. Test lateral-movement hypotheses using sign-ins, remote service creation and
   network observations across hosts. Co-observation and a graph path are leads,
   not proof of execution or causality.
5. Assess possible collection and exfiltration from available file and network
   evidence. State missing telemetry and competing explanations explicitly.

## Report defensible results

Use category, outcome and role filters only where the source has a corresponding
mapping. Otherwise report the coverage gap and inspect the original fields;
never invent a normalized outcome. Cite source hashes and record references for
each proposed finding. Keep observations, hypotheses and confirmed findings
separate. The analyst decides which proposed findings are confirmed. The signed
methodology package is not evidence and cannot substitute for an evidence hash.
