# Skill use receipts and export V7

This proposal is for reviewers implementing progressive skill loading. It fixes
new encoding vectors before any skill text can enter an investigation. Local
installation already has its separate [contract](skills-installation-contract.md).
This document and its synthetic vectors do not implement or enable these formats.

## Scope and unchanged boundaries

Add typed case events `SkillSnapshotV1` (`skill-snapshot-v1`) and `SkillLoadV1`
(`skill-load-v1`). Keep the current signed-entry canonical envelope, its signature
challenge, the current seal inventory V2 bytes, Parquet V3 and mapping receipts.
Skill resources are methodology, never evidence or a source manifest. No skill
hash can satisfy a finding's evidence citation. Existing tool/policy/taint,
approval, context, token, cost and output limits still apply.

Export becomes V7, with magic `IRMIND-EXPORT-V7\0` and header version 7. Pre-1.0
case/export compatibility follows the published policy: preserve the producing
binary or re-ingest verified originals. Existing files are never rewritten when
opened. An incompatible creator/format produces the explicit version guidance.
No V6 reader silently accepts the new records.

The version-named `LargeCaseExporter::export_case_v6` becomes
`export_case_v7`, with the same arguments and return type:

```rust
fn export_case_v7(
    &self,
    id: &CaseId,
    path: &Path,
    source_root: Option<&Path>,
    include_originals: bool,
    cancel: &CancellationToken,
) -> Result<String, AppError>;
```

This is an explicit proposed port change, not a V6 method returning V7 bytes.
The unversioned `CaseExporter` and `ExportVerifier` signatures stay unchanged.

## Canonical encoding

Each event payload is its exact lowercase label above, a colon, and lowercase hex
of UTF-8 JSON. Use fixed struct field order, explicit nulls, no whitespace outside
strings and path-byte-sorted files. Reject unknown/duplicate fields, extra bytes,
uppercase hex, noncanonical JSON and inconsistent redundant fields. Hash a
snapshot as SHA-256 of `irmind-skill-snapshot-v1\0` followed by that JSON. This is a
new typed methodology identity, distinct from `EvidenceHash` and `SkillDigest`.
The existing package commitment remains `irmind-skill-package-v1`.

All current package, path, metadata and Unicode checks still apply. Limit each
encoded payload to 768 KiB and every serialized export frame to the unchanged
1 MiB ceiling. At most 256 distinct snapshots and 16 MiB of original package text
may be retained in one case; refuse a new use before exposing text if full.
These caps bound offline verification state as well as ingestion memory.

### SkillSnapshotV1

Fields, in this exact order:

| Field | Meaning and validation |
| --- | --- |
| `format_version` | Integer 1. |
| `name` | Validated skill name. |
| `skill_version` | Exact metadata version. |
| `target_schema` | Current supported common-event schema; never an implicit upgrade. |
| `interpreter` | `irmind-skill-interpreter-v1`; unknown interpreters are unsupported. |
| `package_sha256` | Recomputed package commitment, lowercase 64-hex. |
| `origin` | `bundled`, `organization` or `analyst`; a label is not authorization. |
| `release_inventory_sha256` | Compiled inventory commitment for bundled content; otherwise null. |
| `admission_operation_sha256` | Exact approved global operation hash for installed content; otherwise null. |
| `files` | Complete original `{path, contents}` inventory, sorted by path. |

The two authorization references are mutually exclusive and mandatory for the
corresponding origin. An Analyst-signed snapshot freezes the exact reviewed
package in the case before its first full load. For installed content, the
admission proof must be an Analyst-signed, active `skill-installation-v1` snapshot
with exactly matching origin, name, version and package. The live application
also checks current global authorization, not just an old receipt. A complete
global-chain audit is separate: an exported proof authenticates an approval,
not the absence of later operations in an unrelated global history.

Bundled content must exactly match the compiled release inventory. The snapshot
binds that inventory hash and the case's Analyst signature. Offline verification
authenticates what the analyst recorded; it does not claim independently to
verify the publisher's release signature. That remains the release-verification
procedure. Bundled content still passes the guard and remains UNTRUSTED.

### SkillLoadV1

Fields, in this exact order:

| Field | Meaning and validation |
| --- | --- |
| `format_version` | Integer 1. |
| `snapshot_sha256` | A preceding authenticated snapshot in this case. |
| `turn_id` | Canonical UUID of the actual turn and UNTRUSTED nonce. |
| `call_id` | Bounded validated tool-call id, or an engine-generated manual invocation id. |
| `resource` | Exact inventory path, never an arbitrary filesystem path. |
| `byte_start`, `byte_end` | Original UTF-8 byte range within that resource. |
| `guard_id` | Bounded guard identity/fingerprint, at most 128 printable ASCII bytes. |
| `guarded_text` | Exact bounded guard output before transport nonce wrapping. |
| `guarded_text_sha256` | SHA-256 of those exact UTF-8 bytes. |
| `guarded_bytes` | Exact UTF-8 byte count, checked against text. |
| `guard_detection_count` | Bounded count; no raw detection text is trusted. |
| `result` | Closed enum: `loaded`, `blocked`, `unavailable` or `limit`. |

A successful load uses a current authorized immutable snapshot and screens that
exact range. No silent truncation of a method: exceeding the per-load or per-turn
budget produces `limit` with empty text. Other unsuccessful results also have
empty text and its corresponding hash. A blocked load never creates an active
method. Unknown skills still receive a normal denied tool result; they cannot
manufacture a snapshot reference.

Record loads with the Agent key and verify its existing trusted key binding.
The root composes the existing `Signer`/`Verifier` capabilities for that role;
installation and snapshot admission remain Analyst actions. No new signing port
or private-key access is proposed. Append the receipt durably before any full
content is exposed. A failed signature/append returns no methodology text.

Maintain four distinct package loads, eight resource reads and 64 KiB of guarded
text per turn, plus the smaller existing context/token/cost budgets. Repeated
reads consume the budgets and get separate receipts. The engine pins the active
method, checks declared tools before ordinary policy/approval evaluation and
attributes calls itself. A model-supplied omission cannot remove that attribution.

## Verification and export

Verify snapshot commitments, metadata, supported interpreter, authorization
references and signatures. Verify load references, ranges, counts, results and
output hashes. Display all package/receipt text through the current guard and
terminal escaping; never put it in a system message. Authentication of recorded
guard output is distinct from re-running a pinned guard and comparing its output.
Neither operation executes skill scripts, reads arbitrary paths or uses network.

The V7 stream retains the existing bounded header, audit, evidence, source,
operational, mapping-proof and Parquet sections in their present order. After
the Parquet section add an unsigned-big-endian-u64 skill-admission-proof count
and that many existing bounded `SignedOperation` JSON frames, sorted by their
operation hash. Maximum 256, deduplicated and exactly equal to the non-null
admission references in snapshots. Reject missing, duplicate, unrelated or
altered proofs and trailing bytes. No unrelated global configuration is exported.
Snapshots and loads already travel in the signed audit section; do not duplicate
packages in a second unsigned catalog. A case with no skills has count zero.

A seal binds the final audit hash containing these snapshots and loads. Preserve
the seal inventory bytes; the artifact inventory continues to describe Parquet,
while typed case verification checks all skill references before sealing/export.

## Encoding vectors and required tests

The [vectors](skills-format-vectors/identities.json) use only synthetic content.
[SHA256SUMS](skills-format-vectors/SHA256SUMS) covers the exact files. JSON files
have no trailing newline; the corresponding payload files have one newline for
readability, outside the signed string. The admission hash is a repeated-byte
placeholder, not a real signature or a valid exported case. The export vector
fixes the magic only, not a fabricated valid sealed archive.

Implementation tests must add complete signed export round trips and golden
frames; preserve current historical/current-format goldens until the minor
format change is integrated explicitly. Include altered resource/hash/range,
wrong actor, forged/missing admission, changed origin/inventory, missing snapshot,
unsupported interpreter, guard-output mutation, duplicate/trailing proof and
frame/count limits. No package data may become evidence or a system message.
The obedient fake model must remain unable to bypass declarations, scope,
organization policy or approval through a malicious skill. Failures retain normal
case usability and never expose an unsigned/unrecorded load.
