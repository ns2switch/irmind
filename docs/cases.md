# Cases and logical deletion

A case contains its signed journal, evidence references, Parquet graph, skill
snapshots and subagent branches. Originals outside IRMind's data directory remain
at their recorded locations. Sealing makes a case immutable.

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
