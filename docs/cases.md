# Cases and logical deletion

A case contains its signed journal, evidence references, Parquet graph, skill
snapshots and subagent branches. Originals outside IRMind's data directory remain
at their recorded locations. Sealing makes a case immutable.

## Check the evidence in a case

Run `/evidence` or ask “What have we ingested?” to see the signed source list,
known failed attempts and the indexed event count and time range. IRMind
answers these questions locally. `/evidence <hash>` continues to display a
stored evidence blob.

## Cases and exports from an earlier version

Version 0.7 uses case marker 6, mapped V3 Parquet artifacts and export V10. Use
the creating version of IRMind to open, verify or export earlier cases. To use
the current version, verify the originals with the creating version and ingest
them into a new case. The original case retains its approvals, confirmed
findings and seal.

## Run a signed Sigma scan

Use `/sigma inspect <directory>` to review a local pack. Use
`/sigma import --license <id> <directory>` and confirm the displayed manifest hash
to sign its admission. The case keeps the exact admitted rules in its V10 export
when a run references them.

Run `/sigma run <pack SHA-256> <start UTC> <end UTC>` from an open case. The
v0.7 field table covers the reviewed Windows EVTX Security, Sysmon and PowerShell
channels, Linux authentication, auditd and mapped ECS, AWS CloudTrail, and
Zeek and Suricata DNS, HTTP and connections. It also covers Entra ID sign-in
and audit, Azure Activity, Microsoft 365, Okta, GCP and Kubernetes audit, and
the reviewed Defender, CrowdStrike FDR and eslogger process and related classes.
The [Sigma guide](sigma.md) lists the exact source fields. Coverage depends on the exact logsource, fields and mapping version. IRMind
reports skipped rules, partial scans and rows with unavailable exact fields by
source. A row is indeterminate for a rule when an exact field it needs is
unavailable. This can indicate source manipulation. Review the intact original.
The report explains the coverage gap and cites the signed execution.
Each match proposes an unconfirmed finding tied to an exact evidence row. Review it and
use `/confirm <finding-id>` before publishing a report.

## Publish a signed report

In an open case, use `/report preview en` or `/report preview es`. The report
includes only findings you confirmed that resolve to an exact evidence row.
Check the coverage section for source availability, skill gaps and queries that
reached their result limit.

Use `/report save md en` or `/report save pdf es` to sign and retain the
rendered document in the case. The command shows its SHA-256. Once sealed, the
case includes its published reports in the V10 export. `/verify` checks the
signature, source rows, coverage and rendered bytes. To publish another
revision, use an open case.

## Delete an unsealed case

From an open case, run `/case delete`. From `/home`, select a case with the arrows
and run `/case delete`, or use `/case delete <title or ID>`. The case list shows
this option in its footer. A sealed case cannot be deleted. A case open or busy in
another process must be closed there first.

The confirmation screen shows the title, creation time, number of sources, journal
entries and storage inventory. Type the **exact title or case ID**, optionally
enter a reason, then choose **Sign and delete** and press Enter. Tab and Shift+Tab
move between fields and options; Esc cancels before signing. There is no model or
subagent tool that can perform this operation.

IRMind verifies the case, signs an Analyst global tombstone and commits it with a
durable deletion intent before removing content. A failed signature removes
nothing. Once that intent is committed, the case disappears from normal lists.
If cleanup is interrupted, startup authenticates the global journal and resumes
it. Pending cleanup remains visible in `/cases deleted`; Enter retries it.

Deletion removes case-private files and case-local database records, including
spools, copied originals, proof packages, skill snapshots and subagent branches.
Shared evidence blobs remain while another case references them. Originals
outside the data directory, other cases, installed skills, configuration and the
global signed journal are preserved. Lock files remain as coordination objects.

## Audit deleted cases

`/cases deleted` shows only authenticated tombstones: identifier, title, creation
and deletion times, previous chain tail, entry/source counts, storage measurements
and optional reason. It cannot restore the deleted evidence. Each tombstone is
signed before cleanup and remains in the global journal.

The inventory distinguishes case-private file bytes, referenced shared-blob bytes
and logical database payload bytes. These are **not** a guarantee of reclaimed
filesystem space: shared blobs may survive and SQLite may retain allocated pages.

## This is not secure erasure

Deletion is logical. SSD controllers, snapshots, backups and modern filesystems
can retain earlier content. Use full-disk encryption and an appropriate retention
policy for sensitive evidence; deleting a case does not guarantee physical erasure.

See [configuration](configuration.md) for the status bar and case budgets.
