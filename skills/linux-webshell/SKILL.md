+++
format = "irmind-skill-v1"
name = "linux-webshell"
description = "Correlate suspicious HTTP requests with web-user execution and collected file changes on Linux."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_timeline", "raw_records", "case_add_finding"]
sources = ["parser-linux", "parser-ecs"]
categories = ["web", "process", "file", "network"]
invocable = true
+++
# Linux webshell

## Establish coverage

Experimental; validated with synthetic episodes only. Mapped HTTP and auditd execution core; partial causal coverage. nginx/Apache common or combined formats map web access and explicit status. auditd execve groups map process starts. HTTP alone may not name the server host, and request IDs may be absent. Do not invent host, ancestry or a causal join.

Ask the analyst for nginx/Apache access and error logs, the exact log format, relevant auditd logs and collected web-root metadata/content. Use parser-declarative for custom log formats only after an approved definition is installed. Keep server/vhost provenance, timezone and clock-skew information. Do not make live requests to a suspected webshell.

## Investigate in order

1. Identify the server and vhost from source provenance and collected configuration. Establish web-log format, timezone, retention and audit coverage before correlating timestamps.

2. Inspect unusual uploads, paths, methods, response codes and repeated parameterized requests. A 200 response or a script-looking suffix is not proof of command execution.

3. Follow auditd EXECVE/SYSCALL groups by web-service uid, executable, arguments, cwd and parent process observations. Incomplete groups remain partial; PID alone must not join unrelated processes.

4. Correlate request and process times using available request/session IDs and known skew. Confirm a shell or unexpected child and any collected file creation/modification. Report a temporal association as such when a causal link is missing.

5. Check later execution/network activity and alternative application behavior. Do not execute web content or send payloads to validate the hypothesis.

## Bounded query starting points

Example tool arguments, not a script to execute automatically:

```text
text_search({"query":"GET","event_category":"web","event_type":"access","event_outcome":"success","entity_role":"source","limit":20})
```

For process activity query event_category="process", event_type="start" and inspect mapped actor/subject observations. Do not impose a web-server host filter on HTTP records that lack it. Use raw_records to correlate source IP, request and original audit identifiers.

Start with graph_summary. Results can be sampled, partial or truncated; inspect
those markers and narrow the UTC window rather than silently extrapolating.
Use raw_records with the returned source hash and zero-based record index.

## Confirm before proposing findings

A T1505.003 proposal needs evidence of server-side malicious functionality or a defensible request-to-execution/file sequence, not just an unusual URL. T1059.004 needs actual shell execution. Cite both HTTP and audit/file source hashes and state correlation uncertainty.

## Common false positives

CGI applications, image/document conversion, deployment hooks, monitoring endpoints, legitimate uploads and incident-response tests.

## Boundaries

The declared tools are local evidence reads and finding proposals only. No
collector, script, remote provider or containment action is authorized by this
method. Case scope, organization ceiling, guard, approvals and budgets apply
to every call. If coverage is missing, tell the analyst what is missing and stop
that inference. Only the analyst confirms a finding. The method/package hash
identifies methodology, not evidence of an incident.

## Public references

- ATT&CK web shell (official source; see the public skills guide for the link).
- nginx log module (official source; see the public skills guide for the link).
