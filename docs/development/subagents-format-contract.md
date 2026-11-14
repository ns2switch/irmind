# Subagent ports, canonical records and export V8

Contract proposal for the [approved architecture](subagents-design.md). This is
encoding/interface documentation with synthetic vectors, not runtime code. The
current executable, current golden files and export V7 are unchanged. Review this
contract before implementing one child; parallel scheduling and the panel follow
that verified single-child path. Community types and monetary limits are absent.
[Español](../es/subagents-format-contract.md)

## Scope and coordinated V8 layout

Keep the existing `SignedEntry`, `SignedOperation`, signature challenges, Parquet
V3, source/mapping receipts, seal inventory V2 and the `export_case` port. Add the
closed event kinds below. A producing release updates the current-format marker
and reports its creator version before accepting a case; no legacy reader or
implicit migration is added. Keep the creating executable for old cases.

The companion catalog contract proposes installation/snapshot V2 and a catalog
proof tail. Both proposals define one V8 layout, even when a feature is unused:
retain the V7 sections through skill-admission proofs, then a u64 catalog-proof
count and its frames, then a u64 branch-chunk count and its frames. Both counts
are present, possibly zero. There is no community-type admission section. Magic
is `IRMIND-EXPORT-V8\0`; `HeaderV8` retains the six V7 fields in order (`version`,
`case_id`, `title`, `severity`, `scope`, `seal`), with version 8. These coordinated
V8 sections and the catalog's V2 labels are explicit review points, not changes
to an already published format. An adapter lacking a nonempty extension rejects
it; it never skips verification or guesses another layout.

The shared producing case marker is `CaseCreated.version = 4`, with existing
ordered fields `version,title,severity,scope,budget` and mandatory initial budget.
No other CaseCreated field or audit challenge changes. Reject version 3/unknown
markers before case work with creating-version/re-ingestion guidance; do not
invent an exact creator patch from the marker. `case-created-v4.json` fixes these
bytes. This marker bump is part of the contract proposal, not current code.

## Application boundaries

New names below describe proposed application types; no trait is added by this
PR. `SourceDecoder`, `SourceMapper`, `LlmPort`, `Signer`, `Verifier`, existing
`AuditLog::append_batch` and `EnginePorts::new` keep their signatures. An optional
`EnginePorts::with_subagents(SubagentPorts)` supplies the adapters; absence means
subagents unavailable, never an unrestricted graph fallback.

```rust
pub struct SubagentPorts {
    pub branches: Arc<dyn SubagentBranchStore>,
    pub queries: Arc<dyn TaskEvidenceQueries>,
    pub analyst: Arc<dyn AnalystPlanInteraction>,
}

pub trait SubagentBranchStore: Send + Sync {
    fn stage(&self, case: &CaseId, chunk: &CheckedBranchChunk,
        cancel: &CancellationToken) -> Result<StagedBranchChunk, AppError>;
    fn publish(&self, staged: StagedBranchChunk)
        -> Result<PublishedBranchChunk, AppError>;
    fn read(&self, case: &CaseId, reference: &BranchChunkRef,
        cancel: &CancellationToken) -> Result<BoundedBranchBytes, AppError>;
    fn discard(&self, staged: StagedBranchChunk) -> Result<(), AppError>;
}

pub trait TaskEvidenceQueries: Send + Sync {
    fn execute(&self, view: &VerifiedTaskQueryView, query: TaskEvidenceQuery,
        cancel: &CancellationToken) -> Result<TaskEvidenceResult, AppError>;
}

pub trait AnalystPlanInteraction: Send + Sync {
    fn review<'a>(&'a self, preview: &'a SafePlanPreview,
        cancel: &'a CancellationToken) -> PortFuture<'a, AnalystPlanChoice>;
}

pub trait EngineEventSubscription: Send {
    fn poll(&mut self, cursor: EventCursor, max: u16,
        cancel: &CancellationToken) -> Result<EngineEventBatch, AppError>;
}
```

`StagedBranchChunk` is a non-Clone owned handle to a private pending file;
`PublishedBranchChunk` binds ordinary SHA-256, length and a hash-derived path.
The store grants no trust or signing capability. Dropping/discarding an unpublished
handle cleans it; publication syncs file/directory before the main audit append.
`BoundedBranchBytes` cannot exceed 1 MiB. Failed publish/append exposes no result
or approval. Unreferenced published chunks are diagnostic cleanup; committed
chunks are never deleted by this API. Reuse Unix 0600/0700 and Windows user ACLs.

`VerifiedTaskQueryView` has private fields and no deserializer: case, task, frozen
query generation, authenticated source-set identity, narrower typed scope and
current policy fingerprint. Only the broker creates it after validation. The
query enum covers `EvidenceSearch`, `EvidenceRead`, `GraphSummary`, `EntityLookup`,
`Neighbors`, `Timeline`, `Path`, `TextSearch` and `RawRecords`, with the existing
validated argument/result types and `GraphQueryFilter`. All variants filter by
this view before aggregation, sampling, expansion, sorting and result limits.
`RawRecords` additionally uses the existing authorized `SourceEvidenceReader`.
Unsupported views fail `TaskSourceViewUnsupported`, not an unfiltered call.
Remote calls use the same task lease in the normal policy/approval dispatcher.

`AnalystPlanChoice` is Start or Cancel from the trusted in-process UI adapter,
not model JSON or an engine event. The signed configuration preference
`confirm_all_subagent_plans` defaults to false. A displayed plan at or below 25%
may return automatic Start only with that preference disabled; otherwise the UI
waits for explicit Start. Above 25%, explicit Start and Analyst-signed consent
are mandatory regardless of preference. The choice carries the displayed plan and
budget commitments back for comparison. The broker, which alone holds the
Analyst signer, creates the signed consent when required. No model tool accepts
a choice, approval signature, `confirmed` flag or source-view capability. A
noninteractive caller with no analyst interaction returns `PlanPending`; no
noninteractive switch can bypass threshold consent.

The broker is one application service using existing case locks, append_batch,
crypto and cancellation, not another independently authoritative store. Its
operations are prepare → review → admit, reserve-step → checkpoint → settle,
and cancel-task/turn. Task leases, prepared plans and reservation tickets have
private fields; callers cannot construct them from strings. A case transaction
serializes budget transitions across processes. Do not hold it during UI/model/
network waits. Waiting adapters use bounded queues and independent cancellation/
deadline checks so a blocked callback cannot stop time-limit enforcement.

## Visible plan and reservation state machine

A safe preview shows all tasks, six-type IDs, source subsets, quotas and case
remaining values. No child starts before this display. Above the threshold, or
with Confirm all subagent plans enabled, Start is an explicit analyst action.
Other displayed plans auto-start by default; cancellation remains available at
any time. The preference is changed only by an Analyst-signed global configuration
operation, never a model tool or caller-supplied flag. One pending preview per
case bounds UI state; child work may run in parallel only after start.
A preview hold reserves capacity but cannot dispatch anything. Expired/cancelled
unused preview holds can be released with a signed reason; incurred/uncertain
execution reservations cannot be refunded as unused.

Under the lock, compute effective allocations as the minimum of the signed case
allocation and current organization limits. Subtract charged usage and all other
outstanding top-level holds. Exclude this exact preview's own hold when rechecking
its original threshold, so it is not subtracted twice. Child/request slices are
inside the top-level plan allocation, not additional case reservations. The plan
includes its coordination/summary allowance plus every child, without overlap.

For proposed tokens T and calls C and recomputed remaining RT/RC:

1. Reject if T > RT or C > RC, any required round/byte quota fails, or arithmetic
   overflows. Never divide by a remaining value.
2. Require signed consent iff `(u128(T) * 4 > RT) || (u128(C) * 4 > RC)`.
   Exactly 25% does not trigger it. Apply to the whole plan, not each child.
3. Append the Agent plan, display its exact commitment, obtain explicit Start
   when required (otherwise record the displayed automatic start), and for a
   threshold plan append an Analyst `SubagentPlanApprovalV1` before execution.
4. Recompute policy, consumption and other holds at admission under the same
   transaction. Changed inputs require a new preview/consent; a stale signature
   does not authorize a revised plan. Then convert the unused hold to execution.

start_plan is unique per plan: duplicate Start/consent cannot launch children
twice, and recovery never replays a provider call. A retry is a new plan/task.

A model cannot split one plan into children to avoid the aggregate test. Each
separate later plan also uses current remaining amounts. Existing call charging
at Allowed/ToolDispatch and cloud-byte charging remain authoritative: a request
slice or checkpoint does not charge those events a second time. Model tokens and
rounds, including compaction/summaries, share the parent turn/case quotas. Keep
uncertain provider usage conservatively reserved. At exhaustion retain a partial
terminal result; request a final model summary only if its reserve fits, otherwise
produce the existing local completed-work summary.

Cost has no reservation, cap or authority in v0.5. Display an estimate only with
sufficient pricing/usage, otherwise unavailable. No community compiler/store,
installation action, executable type file or recursive delegation exists.

## Canonical encodings and identities

All JSON below is exact UTF-8: fixed struct key order as the vectors, explicit
nulls, integers only, no insignificant whitespace or trailing newline. Reject
unknown/duplicate fields, noncanonical bytes, unknown codes and oversized data
before allocating collections. Resource strings use existing validated domain
constructors; hashes are 64 lowercase hex and UUIDs canonical lowercase. Times
`at`/`deadline_at` are existing unsigned operational seconds, not source timestamps.
Untrusted text is screened/escaped on every presentation and never enters system.

For domain D and canonical JSON J, `Id(D,J) = SHA256(UTF8(D) || 00 || J)`.
A main-chain payload is `<lowercase-event-label>:<lowercase-hex(J)>`, using the
unchanged audit envelope and Actor key. The new labels match the domains below
without the leading `irmind-`. Evidence is null for methodology/control records.
Only the existing fixed trusted Agent binding signs Agent records; the tool/model
never supplies a signing key or actor. No new credential is introduced.

| Record | Ordered fields after `format_version = 1` | Domain / actor |
| --- | --- | --- |
| `SubagentSourcePageV1` | case_id, ordinal, sources | `irmind-subagent-source-page-v1`; Agent. |
| `SubagentSourceSetV1` | case_id, count, pages | `irmind-subagent-source-set-v1`; Agent. |
| `SubagentTypeSnapshotV1` | case_id, inventory_sha256, type | `irmind-subagent-type-v1`; Agent. |
| `SubagentPlanV1` | plan_id, case_id, turn_id, ordinal, parent_checkpoint_sha256, budget_checkpoint_sha256, policy, case_limits, usage, prior_reserved, remaining, reservation, coordination, deadline_at, tasks | `irmind-subagent-plan-v1`; Agent. |
| `SubagentPlanApprovalV1` | plan_sha256, budget_checkpoint_sha256, remaining_tokens, remaining_calls, reserved_tokens, reserved_calls, decision | `irmind-subagent-plan-approval-v1`; Analyst. |
| `SubagentReservationV1` | operation_id, plan_sha256, task_id, request_ordinal, action, purpose, amount, parent_operation, cause_sha256, accounting_audit_sha256 | `irmind-subagent-reservation-v1`; Agent. |
| `SubagentCheckpointV1` | case_id, task_id, first, last, count, previous_checkpoint, entries_sha256, chunk_sha256, chunk_bytes, admitted_sources, terminal | `irmind-subagent-checkpoint-v1`; Agent. |
| `SubagentResultV1` | case_id, task_id, checkpoint_sha256, status, guarded_summary, summary_sha256, sources, coverage, usage, pending_approvals | `irmind-subagent-result-v1`; Agent. |

`format_version` is always first. Page sources are unique sorted evidence hashes,
max 256 per page. A set lists contiguous page IDs in ordinal order, max 64 pages /
16,384 sources; every source must belong to the authenticated case query snapshot.
Publish pages before the set and the set before a referring plan. At most 256 sets
and 65,536 source references across distinct sets per case; reuse identical sets.
New task-owned evidence needs an earlier main-chain source receipt and checkpoint
admission, not a model-added hash or a sibling's concurrent data.

The inventory is a canonical array sorted by codes 1–6: triage, cloud, endpoint,
network, kubernetes, threat-intelligence. Each entry has `code,id,version,tools,skills`;
tools/skills are unique ASCII-sorted current IDs. Version is `1`.
`Id(irmind-subagent-type-inventory-v1, inventory)` binds the exact declarations in
[bundled-types.json](subagent-format-vectors/bundled-types.json). A snapshot must
match that compiled release inventory; unknown/community IDs are unavailable.
Names/descriptions remain guarded methodology and the 16 KiB shared catalog cap
from the architecture applies. The inventory is a proposal for review, not code.

Plan IDs are SHA-256 of `irmind-subagent-plan-id-v1\0`, 16-byte case UUID, 16-byte
parent turn UUID and big-endian u64 plan ordinal. Task IDs hash
`irmind-subagent-task-id-v1\0`, the 32-byte plan ID and u64 task ordinal. Plan
ordinals start at one, task ordinals at zero. They do not depend on completion
order or model-generated titles. Every task fixes `task_id,ordinal,
type_snapshot_sha256,nonce,source_set_sha256,remote_scope,objective,
skill_snapshot_sha256,budget,deadline_at`, in that order. Nonces are distinct
engine-generated UUIDs. Objectives are at most 2,048 bytes. Scope uses the
existing typed `CaseScope` encoding, validated as narrower than case and policy;
null remote_scope grants no remote capability. The plan also records its parent deadline_at; every task deadline is no later.
Enforcement uses the monotonic cancellation/deadline service, not a model timestamp.
Optional skill references bind the
current admitted snapshot and do not broaden the type/tool intersection.

Resource objects are `tokens,calls,rounds,cloud_bytes`, all checked u64. Tokens,
calls and cloud bytes are case totals; the rounds slot is the parent-turn
allowance/usage, not a new lifetime case-round quota. Policy
snapshot key order is fixed in plan.json; its fields mirror the current rules,
including denied tools and scope, with no monetary fields. Runtime reads current
policy, not the model's snapshot. Offline verification authenticates the recorded
policy and recomputes its intersections; it cannot prove an external organization
administrator's intent from a local file. No new organization signing key is assumed.

Approval decisions are approve/cancel. A required approval must precede execution,
match the exact plan and budget checkpoint, and recompute the remaining/reserved
numbers from authenticated history/reservations; numbers alone are not proof.
Reservation actions are hold_preview, start_plan, reserve_request, settle_request,
release_plan and expire_preview; purposes are plan/model/tool/cloud. Operation IDs hash `irmind-subagent-operation-id-v1\0`, plan ID32, a one-byte
task-presence flag and optional task ID32, u16 action code (1–6 in the order above),
u16 purpose code (plan=1, model=2, tool=3, cloud=4), and u64 request_ordinal, all
integers big-endian. Plan transitions use ordinal zero, request steps start at one.
A transition references its unique operation ID/parent and prior plan, approval or checkpoint
cause. Request slices cannot increase the plan envelope. Settlement requires an
already committed prefix, never a future result or self-reference. Release only
proven unused amounts; count each unique execution once. Wrong actors, stale
checkpoints, overdrawn slices or duplicate settlement fail verification.

Child dispatch uses exactly one existing Allowed (local) or ToolDispatch (remote)
accounting event, never both. Its structured attribution payload is ordered
`version,tool,reserved_bytes,task_id,call_id,proposal_sha256,
reservation_sha256,arguments_sha256,source_set_sha256`, version 1. Preserve the
existing object_read reservation fields/rules; verify additional task bindings.
The later settlement's accounting_audit_sha256 references that event (or the
unchanged ModelUsage event for model tokens), and does not charge it again.
Unknown usage keeps this field null and retains the conservative reservation.
No dispatch can occur before the required plan/tool consent and durable proposal.

## Branch entries, checkpoints and acyclic order

A wire entry is `{body,hash,signature}`. Body field order is
`format_version,case_id,turn_id,task_id,nonce,seq,at,kind,payload,prev,public_key`.
The hash is `Id(irmind-subagent-branch-entry-v1, body)`; Ed25519 signs those 32
hash bytes, exactly as current case entry signing. Public key is hex32 and must
match the trusted case Agent key; signature is hex64. Sequence starts at one and
prev is zero32 only for that first entry. Later prev equals the previous hash.

| Kind code | Payload fields, in order |
| --- | --- |
| 1 model request | call_id, model, messages_sha256, reservation_sha256, round, output_limit |
| 2 guarded reply | call_id, guarded_text, truncated, tool_calls, usage |
| 3 tool proposal | call_id, tool, arguments, allocation_sha256, tainted, source, guarded_excerpt |
| 4 tool result | call_id, proposal_sha256, decision_audit_sha256, reservation_sha256, guarded_text, sources, partial |
| 5 skill load | exact current SkillLoadV1 payload string; snapshot in the main chain, turn_id = this task nonce |
| 6 compaction | guarded_text, text_sha256, replaced_first, replaced_last |
| 7 budget notice | resource, reserved, consumed, limit, partial |
| 8 terminal | status, guarded_summary, summary_sha256, sources, coverage, usage, reservation_ids, pending_approvals |

Tool IDs are from the closed existing catalog; arguments use validated current
schemas and explicit ASCII key order. Tool calls have current bounded IDs;
provider reasoning is absent. Source refs are `{hash,index}`, bounded and sorted
by hash/index; source, scope and citation membership are checked, not inferred
from text. Loaded skills share the parent's four/eight/64 KiB limits. Kind 5
payload is a canonical string, not an alternate deserializer for skill receipts.
All fixed result/summary text stays UNTRUSTED even after Agent signatures.

A chunk is canonical JSON of a nonempty contiguous entry array. Its file hash is
ordinary SHA-256 of those exact bytes. The ordered entry commitment is SHA-256 of
`irmind-subagent-entry-set-v1\0 || u64(count) || entry_hash_1 || ...`, with fixed
32-byte hashes in local sequence order, not hash-sorted. Previous checkpoint is
null only for the first one. Check first/last/count, entry/hash/signature chain,
file bytes/hash and exact chunk membership. No duplicate or overlapping prefixes.

Order: publish signed proposal prefix → main checkpoint → policy/Analyst tool
decision and request reservation → tool/source effect → later result prefix →
checkpoint → settlement. A terminal entry carries summary/status and reservation
references, never its future checkpoint. The main result follows the final
checkpoint/settlement and repeats the committed summary. A checkpoint cannot
include the result of an approval that depends on that same checkpoint. A DAG
cycle, dangling decision or missing material is a failure, never a partial-success
marker. Plan threshold consent and individual tool approval are separate.

Checkpoints merge by frozen plan/wave/task ordinals and local sequence. Record real
timestamps and waves; do not rewrite them to simulate reproducibility. Fixed-clock
scripted fixtures compare bytes with 1/2/4/N workers; real provider responses are
not promised identical. Cancellation retains the authenticated prefix, charges
incurred/unknown usage and produces partial/cancelled state without restarting tools.

## Frames, event stream and verification limits

Keep the 1 MiB serialized-frame ceiling. Payload: 256 KiB; chunk: 64 entries and
1 MiB total, whichever comes first; task: 4,096 entries / 16 MiB; case: 256 tasks /
256 MiB and at most 16,384 chunks; summary: 16 KiB. Counts are checked u64 and
frame lengths big-endian u64. The branch tail after catalog proofs contains a
chunk count, then for each chunk a descriptor frame and one raw chunk frame.
Descriptor fields are `task_id,first,last,chunk_sha256,chunk_bytes`, sorted by
task ID then first sequence. Include exactly the chunks referenced by main-chain
checkpoints, including cancelled/error prefixes. No missing, extra or trailing frames.

The in-process event stream uses `{version,session_id,cursor,case_id,turn_id,
task_id,kind,payload}`; version 1, cursor monotonic within a session. Kinds cover
plan preview/consent-required, messages, rounds, proposals/results, approvals,
status, coverage, budget and checkpoints. It carries safe projections, never keys,
raw reasoning or approval capabilities. Queue caps: 1,024 events and 1 MiB aggregate;
individual deltas at most 16 KiB. Plan preview references an immutable safe view
(max 64 KiB), not full source/hash arrays. Coalesce transient deltas; backpressure
and cancellation preserve terminal/approval/budget/durability events. Reconnect
rebuilds committed state and cannot repeat calls. New transport/engine API is absent.

Before seal/export, verify Agent/Analyst bindings, type/source snapshots, plan
consent, reservations, all branch prefixes, approvals, usage, skill/source/mapping
proofs and citations. The seal's main audit hash commits checkpoints; seal V2
bytes stay unchanged. Export verification is streaming/offline, executes no model
or downloaded code, and distinguishes signed claims from source reconstruction.
Missing committed material fails; unknown cost is merely unavailable, not a failure.

## Golden vectors and implementation gate

[subagent-format-vectors](subagent-format-vectors/README.md) fixes identities,
source pages, plan/consent, signatures using the unchanged audit challenge,
Agent branch entries, checkpoint commitments, reservation/result bodies and V8
magic/tails. Exactly-25%, +1 token/call, zero remaining and wide-integer boundary
cases are explicit; the u64-maximum row tests arithmetic only and remains invalid
as a case policy above the existing fixed maxima. SHA256SUMS covers all fixture files. Public keys are synthetic;
no real key, environment secret or production trusted-key list is created.

These are independently verifiable encoding fragments with synthetic authenticated
anchor inputs, not complete runnable cases/archives. Current IRMind must reject
future records. Implementation tests must construct full signed cases and check
all fragments plus wrong actors, modified keys/bytes, missing consent, changed
budget after preview, model bypass, scope escape, duplicate accounting, cycles,
1 MiB limits, cancellation and native independent export verification. Do not
replace a full-case test with a successful fragment signature check.
