# Forensic skills design

This proposal is for maintainers and contributors building the v0.4 skills
feature. It defines data packaging, bounded loading, signed authorization and
tests. It does not implement skills, introduce ports or change signed formats.
The [roadmap](roadmap.md#v04-forensic-skills) tracks the intended delivery.

## 1. Boundaries

A skill is an investigation method, not a plugin or permission grant. It can
explain how to investigate, suggest existing structured queries and identify
missing evidence. It cannot execute code, collect evidence, install modules,
change settings, select credentials, approve calls or confirm findings.
Methodology is not evidence: a skill/package hash cannot satisfy a finding's
evidence reference or be ingested as if it were a source event.

Use the existing [source/mapping separation](source-mapping-design.md) and
[common-event contract](common-event-schema.md). Skills consume their results;
they do not reinterpret raw fields into authoritative categories or roles.
Policy, case scope, the organization ceiling, ContentGuard, budgets and analyst
signatures remain independent of skill content and metadata.

Only fixed IRMind instructions enter the system role. Catalog descriptions,
skill bodies, resources, query results and model-derived summaries never do.

## 2. Package and metadata

Each immutable version is a directory containing `SKILL.md` and optional files
under `queries/`, `rules/` and `references/`. Examples of allowed resources are
structured-query JSON, reference CSV/TOML, Markdown and reference-only Sigma
YAML. Rules are data: the skills feature does not add a rule execution engine.
Shell/Python resources, libraries, binaries, notebooks, archives, executable
permissions, symbolic links and hard-link aliases are rejected. Fenced examples
may contain only supported data formats; Markdown is never executed. Links are
displayed as text and never fetched automatically.

Use TOML frontmatter delimited by `+++`, reusing the workspace's existing TOML
support. This avoids adding a YAML parser for metadata. Unknown metadata fields,
duplicate keys, invalid UTF-8, disallowed controls or unresolved tools fail
validation. A proposed document looks like this:

```toml
+++
format = "irmind-skill-v1"
name = "windows-triage"
description = "Investigate a scoped Windows collection and corroborate findings."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["entity_lookup", "entity_timeline", "neighbors", "text_search", "raw_records", "case_add_finding"]
sources = ["parser-evtx", "parser-hayabusa", "parser-eztools", "parser-velociraptor", "parser-plaso"]
categories = ["authentication", "process", "file", "registry", "network", "iam"]
invocable = true
+++
```

The frontmatter above precedes the Markdown methodology in the same file.
Author and license are bounded declarations, not authenticated identity claims.
Require an explicit license; bundled/community starter content uses
`MIT OR Apache-2.0`. Other licenses require a documented distribution review.
Version is an exact bounded identifier, not a range or instruction to fetch an
update. The target schema and category labels must be supported closed IDs.
Source IDs may identify absent modules; show their availability separately.

Proposed initial bounds are deliberately small:

| Item | Limit |
| --- | --- |
| Name | 48 ASCII characters; lowercase letters, digits and interior hyphens |
| Description | 256 UTF-8 bytes, one line |
| Version / author / license | 64 / 128 / 128 UTF-8 bytes |
| Frontmatter / complete SKILL.md | 8 / 32 KiB |
| Declared tools / sources | 32 / 32 exact IDs; no wildcards |
| Optional resources | 16 files, at most 32 KiB each |
| Whole package | 128 KiB before serialization |
| Relative resource path | 160 ASCII bytes, approved subdirectory and suffix |
| Active model-visible catalog | 32 skills |

Reject absolute paths, dot segments, drive/UNC paths, encoded traversal,
case-folding collisions and duplicate paths. Read regular files without following
links; build a private snapshot before hashing. Resource references resolve only
against its signed inventory, never the host filesystem. Reject a package whose
canonical signed representation would exceed the existing 1 MiB frame limit.
These are proposals for new data, not changes to current ingestion limits.

## 3. Identity, origins and installation

Identify a version by `(name, version, package_sha256)`. Calculate the hash with
the domain `irmind-skill-package-v1` followed by NUL, a big-endian u64 file count
and a length-framed inventory sorted by relative path bytes. Each entry binds a
big-endian u64 path length, its path bytes, a big-endian u64 content length and
the 32-byte SHA-256 of its
exact original UTF-8 bytes. Keep body order, whitespace and resource content;
frontmatter parser/map iteration order cannot affect the inventory. The manifest
does not hash itself. A changed byte creates a different package identity, even
when an author reuses the same version label.

| Origin | Admission and trust |
| --- | --- |
| Bundled | Embed the three reviewed packages and fixed hashes in the binary's build manifest. Verify hashes before registration. They inherit the verified release's provenance; no separate installation signature is needed. |
| Organization | Import an explicitly supplied package. Its organization label does not grant trust or bypass local analyst review and signature. Organization policy may further restrict or disable it. |
| Analyst | Import a selected local package or explicitly downloaded immutable version, review it and sign its admission. No environment-based or automatic discovery grants authorization. |

Bundled skills are available by default, without enabling any LLM, connector or
collection tool. Other packages start as untrusted candidates. The analyst sees
the exact version, origin, license, full methodology, resources, hash, required
tools and coverage before choosing to install and activate. An author name, a
community listing or a matching checksum alone is not an approval.

Reuse the signed global-operation workflow used by declarative definitions:
validate and prepare an immutable private snapshot, then authorize the exact
content and inventory with the Analyst key. Installation, update, activation,
deactivation and replacement are explicit signed operations. Updating stages a
new hash rather than overwriting bytes. Collisions with an active skill or a
built-in command require an explicit replacement/alias choice; there is no
origin-based silent precedence. Failed validation or signing applies nothing.

The signed operation contains the full bounded snapshot, not just a path or hash.
Atomic private-file publication follows the approved-operation recovery pattern.
A crash or a loose-file edit cannot silently authorize new instructions: disable
the affected package, explain the mismatch and offer explicit restoration from
the signed version or review as a new candidate. Unrelated cases still open.
Unavailable interpreters/target schemas disable a package with a clear warning.

Approval authorizes use of that version; it does not make its prose privileged.
Signed third-party content remains tainted at every model/display boundary.

## 4. Progressive loading and tool boundaries

At turn start freeze the enabled, integrity-checked catalog with current policy
and tool availability. The model initially receives only each skill's `name`
and guarded `description`, inside a user-role UNTRUSTED block with the turn nonce.
The catalog is not appended to system instructions. Show missing capabilities
to the analyst instead of advertising a skill as fully applicable.

Propose one local read operation, `skill_read`, to choose an enabled exact skill
ID from that catalog. It accepts no URL, arbitrary path, package bytes or install
action. It loads the guarded methodology; optional resources are separate named
reads from the same immutable inventory. The model cannot install, update,
enable, disable or substitute a package through this operation.

Use normal structured assistant tool calls and linked tool results. Skill text
is wrapped as UNTRUSTED with nonce, hash and origin, using fresh delimiters that
cannot be closed by its contents. Run ContentGuard on descriptions, body and each
resource on every exposure, including cached reads. Blocking guard results are
visible and do not create a usable load. Display text is escaped separately;
canonical signed bytes remain unchanged. A signed load is recorded before text
is exposed, so a custody-write failure cannot lead to unaudited model use.
Use skill-resource provenance (name, version, package hash, resource and byte
range), distinct from evidence provenance. No resource is relabelled as a log
source or promoted to trusted model content.

Proposed per-turn limits are four distinct package loads, eight resource reads
and 64 KiB of guarded full content in total. Also charge catalog/content against
the existing context/token/cost budgets; the smaller bound wins. Refuse an
oversized load with a fixed bounded explanation rather than silently cutting a
method in half. Reloads do not reset budgets. A repeated full read can use the
validated in-memory snapshot, but records a separate use receipt and still
counts toward resource/byte budgets. Never resend provider reasoning.

The trusted engine tracks the active skill context after a successful load.
Every subsequent investigative tool call is attributed to that context; the
model cannot remove the attribution by omitting a field. Required tools form an
additional declaration check, not a permission grant:

`permitted = declared_by_active_skill AND enabled_tool AND policy_allowance`

Policy allowance still includes validated arguments, case scope, the organization
ceiling, taint, approvals and all resource limits. An undeclared call is rejected
before connector execution or approval creation. A missing declared tool is an
availability error, never a reason to enable a connector or obtain credentials.
Only another bounded, audited skill load changes the active method; changing
method never expands the underlying policy/tool permissions. Calls made before
any skill load retain the normal investigation rules.

External enrichment that is declared and within scope still requires the normal
approval when policy says so. A skill cannot approve it, mark a finding confirmed,
turn a policy Deny into NeedsApproval, change Chronicle scope mode, or raise the
organization ceiling. Completed work remains signed on cancellation or a limit.

## 5. Case receipts, history and offline verification

Propose a versioned `SkillSnapshotV1` on first use in a case and `SkillLoadV1`
for every full-content/resource load. These are new proposed typed audit records,
not new strings added by this document to the current implementation.

The snapshot binds the complete package inventory, origin, schema/interpreter
identity and authorization evidence. A bundled snapshot identifies its release
build-manifest hash. An installed snapshot includes the Analyst-signed admission
receipt. Its signature authenticates that exact approval; it does not pretend
to prove continuity of the entire global operational chain. A separate complete
global-chain audit remains possible without exporting unrelated configuration.

The Agent-signed load binds snapshot/hash, exact resource, turn and call ID,
guard version, the bounded guarded text and its hash, byte count and load result.
Hash that text before adding transport-specific nonce delimiters; bind the
envelope/turn identity separately. Keeping the guarded text lets an offline
verifier check its commitment without executing an older guard. It makes no
permission or finding-confirmation claim. Include the selected skill context in
the audit of proposed calls so an exported investigation can explain its method.
A model-generated compacted summary references those receipts and stays guarded
UNTRUSTED user-role context; it cannot replace their original hashes.

Case snapshots preserve versions needed by that case even after a global update
or deactivation. Historical loads are evidence, not permission to load a disabled
skill in a new turn. Recheck current authorization before future loads/calls;
never change the pinned bytes of an in-flight read. Reopening a case does not
automatically load its previous skills into the model.

Export must include used snapshots, admission receipts and load records, so the
offline verifier can authenticate signatures, inventories and references without
downloading a skill or executing it. It must reject missing snapshots, altered
resources, unsupported interpreters and mismatched guard-output commitments.
Authentication of recorded output does not mean rerunning an obsolete guard or
model; label that distinction. Full current-version reconstruction can rerun the
pinned guard where available and compare its recorded output hash.

The implementation must propose the corresponding case/export version impact
and new golden bytes before merging it. Do not silently extend export V6, change
the current seal inventory bytes, raise the frame limit or rewrite old receipts.
This document changes none of those formats.

## 6. Analyst interaction

These are proposed TUI commands, not commands implemented by this PR:

| Entry | Behavior |
| --- | --- |
| `/skills` | List enabled, disabled and unavailable packages, origin, exact version/hash and coverage. |
| `/skills inspect` | Open escaped methodology, declared tools, inventory, admission and signature details. |
| `/skills install` | Open a form for a local package or explicit download; review and sign the candidate. |
| `/skills update` | Select and review one immutable replacement and its differences; no automatic update check/download. |
| `/skills enable` | Explicitly sign activation of an installed, supported package. |
| `/skills disable` | Sign deactivation; preserve existing case snapshots and history. |
| `/windows-triage` | Start the named enabled method through the same application load case, not a second agent loop. |

Values and URLs belong in visible form fields, not shell commands. Normal reserved
keys apply: arrows/Tab, Enter, Esc and Ctrl+C with the existing confirmation.
No single-letter action or executable alias is introduced. Register invocable
skills through the one command registry; menu, palette, completion and help use
that registry. Reserved-name collisions fail visibly; disabled/unavailable
aliases explain why they cannot run.

The TUI labels the active method, reports missing sources/tools and shows each
load/result in chronological order. Loading is local background work and remains
cancelable. It never blocks render ticks. Installation shows its expected I/O
before the explicit analyst action; it is not an agent tool.

## 7. Structured queries and coverage

Query resources use existing tool IDs and argument schemas, not free SQL, SPL,
KQL, shell commands or a general template language. Allow only typed scalar
placeholders in known argument positions, with a bounded substitution count.
Unknown fields, operations or target-schema values fail validation. All filled
arguments pass the ordinary validator and policy again; a template cannot widen
a date window, account, project or host ceiling. Evidence-derived values retain
their taint/provenance after substitution.

An illustrative template for the current graph catalog is:

```json
{
  "tool": "entity_timeline",
  "arguments": {
    "kind": "user",
    "value": "${analyst_selected_user}",
    "event_category": "authentication",
    "event_outcome": "failure",
    "entity_role": "target",
    "limit": 20
  }
}
```

Use the existing category/type/outcome/role filters and scoped entity identities.
An actor and a target with the same spelling remain distinct observations.
Do not join reused PIDs as one lifetime; only documented lifetime identifiers
such as Sysmon ProcessGuid justify that identity scope.

Compare requirements with the signed source/mapping profiles and query coverage.
Extraction-only records, absent mappings and absent fields are explicit coverage
gaps. `unknown` outcome does not mean failure, success or benign. A filtered
empty result is not evidence that an attack did not happen. Show a bounded
coverage warning in the TUI and model result. A skill may suggest manual review
of original fields or additional evidence; it cannot invent a mapping, assign
roles from text, reclassify the stored event or silently remap the case.

## 8. Initial bundled methods and synthetic acceptance episodes

The implementation should deliver three methods; the following are content
outlines, not implemented skills or completed validation claims.

| Method | Proposed methodology | Synthetic episode and expected checks |
| --- | --- | --- |
| Windows triage | Explain scoped analyst-run KAPE/Velociraptor collection. Prioritize direct isolated EVTX, Hayabusa or EvtxECmd, then PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, LECmd, RECmd and SrumECmd. Investigate logons, execution, persistence, lateral movement and possible exfiltration; corroborate independent artifacts. File/cache presence is not proof of execution. | Failed/successful logons, type-3 lateral logon, service/task creation and Sysmon execution with PID reuse. Confirm only supported evidence-linked findings; preserve actor/target/source roles and missing-field warnings. Collection tools are never launched by a skill. |
| Linux triage | Follow SSH failures to access, sudo/su, grouped auditd execution and cron persistence. Use analyst-confirmed legacy year/offset and auditd partial markers. Add journald corroboration with coverage warnings where its semantic mapping is absent. | SSH brute force, a successful login, sudo and cron persistence, plus benign failures and incomplete audit groups. Verify chronology, distinct attempted/target/effective users and no invented process lifetime. |
| AWS credential compromise | Follow CloudTrail identity/session use, ConsoleLogin results, STS assumptions and IAM privilege changes. Limit every lookup to declared accounts/time; separate an API failure from evidence of compromise. | A HuntEval-style synthetic AWS privilege-escalation episode with corroborating IP/session/IAM events and benign actions. Require source-hash citations and analyst-confirmed event/entity/ATT&CK findings, including T1078.004/T1098 only where the episode supports them. |

Each episode follows the [HuntEval isolation contract](benchmarks.md#hunteval-normalized-episodes):
ingest only public source events. The evaluator reads private answers after the
investigation, outside model/tool/evidence context. Include deterministic fake
models, expected event/entity/technique sets, false-positive cases and missing
mapping/source variants. Evaluation never auto-confirms a finding. A real-model
trial is optional, explicit and outside CI; CI never configures a provider.

## 9. Community repository

Propose a separate `irmind-skills` repository, with no executable plugins:

```text
skills/<name>/<version>/SKILL.md
skills/<name>/<version>/queries/...
skills/<name>/<version>/references/...
catalog.toml
LICENSE-MIT
LICENSE-APACHE
CONTRIBUTING.md
```

Use dual `MIT OR Apache-2.0`, DCO sign-off, per-package attribution and a validator
for bounds, hashes, selectors, tool IDs and synthetic episodes. Any exception to
the license must be explicit; a catalog cannot relicense third-party material.
Catalog entries pin immutable commits, paths, sizes and package hashes.

The analyst explicitly chooses an immutable entry and download. Use bounded HTTPS
reads with normal certificate/hostname checks, no credential inheritance and no
automatic redirects to arbitrary hosts. Avoid extracting a repository archive;
fetch only its bounded inventory and selected files. Display host, origin and
expected hash before network I/O, then verify every file and package hash before
review and local signing. A checksum fetched from the same untrusted source
proves consistency, not author identity. Do not advertise it as a signature.

No startup poll, model-initiated download, dependency resolution, git hooks,
automatic pull/update, URL opening or hidden network access is allowed. A
community signature/provenance proof can add information, but never replaces
the analyst's admission or existing policy decisions.

## 10. Verification plan and implementation boundaries

| Contract | Required regression |
| --- | --- |
| Packaging | Stable hash on Windows/Linux/macOS and preserve_order; changed body/resource rejected; duplicate keys/paths, traversal, links, controls and oversized files rejected before admission. |
| Progressive loading | Recording fake sees only guarded names/descriptions initially; full body only after a valid load; no case/skill/evidence/model content in any system message. |
| Malicious skill | Obedient fake follows hostile prose and requests an undeclared supported tool, an out-of-scope call and an instruction to ignore policy. Assert denial before execution, no approval path for organization-denied work and no policy/configuration mutation. Repeat with an Analyst-signed malicious package. |
| Evidence boundary | A fake tries to cite the skill/package hash as evidence or confirm a finding itself. Both requests fail; only existing case evidence and the normal Analyst confirmation are accepted. |
| Declared remote tool | An in-scope external call still enters the normal approval queue with exact arguments and taint origin. Reject/approve with the Analyst key as usual; skill signatures never substitute. |
| Registry | Reserved alias/colliding package rejected; inactive, manipulated or unsupported versions unavailable; changing active method cannot grant baseline permissions. |
| Budgets | Repeated reads cannot reset byte/token/cost/round budgets; bounded rejection visible; cancellation retains completed receipts. |
| Durability | Simulate crashes before/after signed authorization and atomic publication; failed signature/write leaves no partly authorized version; recovery is explicit. |
| Offline case/export | Missing/tampered snapshot, forged admission, altered load reference or guard-output hash invalidates the relevant verification; no filesystem, network or downloaded-code execution during verification. |
| TUI | TestBackend/PTy exercises list/inspect/install/update/disable/invoke at 80 columns, escaped hostile text, missing coverage, background loading and render ticks. |
| Episodes | All three synthetic methods reach evidence-linked proposals/analyst confirmations; private expected answers never enter any recorded model request or evidence inventory. |

Place validated metadata/identities and bounded catalog views inward in domain/app;
application cases own authorization and case receipts. Infrastructure owns atomic
private snapshots and explicit transport. Bundled packages are data modules with
build-manifest hashes. TUI and CLI are presentation over the same application
cases. Native arbitrary-code skill plugins and new product modules are outside
this proposal.

The implementation will need reviewed additive catalog/snapshot/read boundaries,
typed audit records and export support. Specify exact Rust contracts and current
golden changes in implementation PRs before merging; this document does not
authorize a hidden change to an existing port or format. No new production
dependency is required by the proposed TOML/data format; any later need requires
separate dependency review.

Pre-1.0 minor versions may change skill, definition, case and export formats
without migration, like the rest of IRMind. Keep the executable that created a
case or re-ingest verified originals into a new case. Unsupported skill versions
are disabled with an explanation, not executed through a historical interpreter.
Within a supported version, signatures, hashes, snapshots and deterministic
verification remain mandatory. The design does not promise cross-minor readers.
