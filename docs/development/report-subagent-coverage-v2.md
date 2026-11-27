# Subagent skill coverage in V10 reports

> The V2 coverage body remains active. The [case 7 and V11 contract](case-7-export-v11-contract.md) supersedes the V10 outer archive.

**Status.** Approved for the v0.7 report proof objects.

[ReportCoverageV1](sigma-report-proof-objects.md#report-objects) references a
skill load using the sequence and hash of an entry in the main case chain.
A delegated skill load is stored in a signed child branch. Its sequence
belongs to that task. Two children can both have a load at sequence 3
and a gap at index 0. The V1 ordering would treat those coordinates as
duplicates, and neither reference would resolve in the main chain.

## ReportCoverageV2

Keep the four V1 lists in their original order. Replace the object tag
with `irmind-report-coverage-v2\0` and append a fifth list after the partial
Sigma runs. The fifth list is always present. Its count is big-endian u64.

A delegated skill gap entry contains the following fields in order.

| Field | Encoding |
| --- | --- |
| Main-chain checkpoint | Existing audit reference with u64 sequence and 32-byte entry SHA-256 |
| Task ID | 32-byte digest |
| Branch load sequence | Big-endian u64 in the inclusive range 1–4,096 |
| Branch load SHA-256 | 32-byte digest |
| Gap index | Big-endian u64, zero-based within the declarations in the pinned skill |

Sort and require uniqueness by checkpoint sequence, task ID, branch load
sequence and gap index. Use the verified checkpoint whose inclusive
branch range contains the load. Resolve it in the main chain at or before
the report input checkpoint. Verify that the checkpoint belongs to the
same task, authenticates the exact chunk, and includes the signed branch
entry with the given sequence and digest. The branch entry must be a
successful skill load and must resolve to its authenticated skill snapshot.
Verify the gap index against that snapshot. Derive the whole coverage
inventory again and reject omitted, duplicate, extraneous or stale references.

The report includes loads committed at its input checkpoint. Entries that
arrive later belong to a later report. Apply the existing proof size,
list and aggregate bounds. The V10 report section still uses proof kind 2.
`ReportPublishedV1` continues to commit to the whole proof set, including
the exact SHA-256 of the coverage object. The header, section counts, seal,
receipts and the subagent format keep their approved encodings. Existing
V1 vectors remain intact. New v0.7 publications use V2 from the start.

## Independent vectors

The [generator](../../crates/testkit/fixtures/contracts/report_coverage_v2.py)
and [vectors](../../crates/testkit/fixtures/contracts/report_coverage_v2.json)
cover an empty child list, two tasks using the same branch sequence and gap
index, a duplicate, an invalid zero branch sequence and an omitted child.
The omitted child is syntactically valid and fails against the recomputed
checkpoint inventory. Include the V2 coverage in a publication receipt and
report section using the existing encodings for both.
