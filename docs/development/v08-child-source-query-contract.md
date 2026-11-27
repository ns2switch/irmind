# Source queries from a cloud subagent

**Status.** Proposed implementation of the approved source-query design's
[deferred child allocation](source-queries-deferred.md). Exact-version
remote-original verification remains a separate contract. Use the existing
three read-only adapters and their admission and billing proofs. Tests use
simulated providers.

The [admission order amendment](v08-child-query-admission-order.md) is open for
review. It addresses the attribution gap before query-specific approval.

## Plan and admission

Write `SubagentPlanV2` for every new case-8 plan. Keep every
`SubagentPlanV1` member with its existing semantics, set `format_version`
to 2 and add a required `query_resources` array. Domain and audit kind
are both `irmind-subagent-plan-v2`. Serialize this V2 body as J.
Keep task ID calculation, existing obligation to use a fixed source set,
and present plan-approval and checkpoint codecs. They reference the V2
plan digest through their existing fields. An empty array grants no query
allocation.

The entries are `{task_id,sources,scope,scan_bytes,retained_rows,retained_bytes}`
in ascending task digest order, unique. Each assigned task has the bundled
cloud type with a new explicitly approved V2 tool set and local source policy.
At most 32 configured query source IDs per task, sorted and unique.
`scope` is the existing canonical serialized remote case-scope string
narrowed to those explicit sources, the current case, the organization's
ceiling and the planned time window. A local-only scope cannot be used here.
Adopted source configuration, provider settings and policy are rechecked
before the query. One source can represent only its existing configured
account/project/workspace and region scope. Query resource IDs cannot
occupy the local evidence-source set.

Reserve the full plan's scan and both retention dimensions before any child
starts, in the same authoritative case transaction as the broker's other
plan resources. Sum checked u64 shares across tasks. Recompute case remaining
from authenticated source-query allocation, settled usage and prior holds.
Reject a positive amount above remaining; a positive demand with zero
remaining rejects rather than requesting a bypass. The existing tool-call
and ordinary budgets still apply. The displayed plan shows original sources,
per-task and total reservations and effective time windows. Apply the 25%
threshold to each additional dimension across the whole plan, using
`u128(reserved) * 4 > u128(remaining)`. Equal to 25% uses the normal
preference rule; zero-of-zero contributes nothing. If any dimension crosses
the threshold, require the existing signed Analyst plan decision referencing
the complete V2 digest before starting a child. Individual query approvals
remain independent. The model grants neither plan nor query approval.

## Dispatch, replay and settlement

For each remote child query, place the normal branch proposal in a committed
prefix first. Before any provider preflight, the broker validates the
active task lease, assigned source, effective scope and remaining child slice
and applies the existing preflight and approval policy. Provider interactions
that estimate cost still require that authorization. An Agent case entry `irmind-child-source-query-v1` binds
`{version,case_id,plan,task_id,query_plan,checkpoint,branch_proposal,source_id,source_set,budget_checkpoint}`.
Each digest refers to authenticated prior material. `query_plan` is the
existing signed query-plan content ID for the typed request with its exact
compiled translation and preflight. `branch_proposal` points inside the
cited checkpoint. The referenced source and approved fields must match the
intersection. Record the binding and the existing durable query reservation
atomically inside the case transaction before the broker issues a dispatch
permit. A permit has no use outside that task, current lease and exact
reservation. The existing dispatch record and provider-specific uncertainty
rules still govern network execution. A query resource debit comes from the
child share; root queries and neighboring children cannot borrow reserved
capacity. Count one ordinary tool call and one source-query settlement,
without double accounting. Reuse the existing query executor,
capture storage, decoder and mapping ports.

The result is an ordinary derived capture with its existing page verification,
provenance and partial marker. Make it available only through the case-local
view afforded to that child and the parent after the main chain authenticates
the capture and a later branch checkpoint references it. A neighboring child
does not obtain its source set. The result never enters the branch before
its approved evidence receipt. Distinguish quota spent, retained evidence,
and admitted but in-flight amounts. Release proven unused shares once.
Unknown provider execution retains the ambiguous hold as defined by the
adapter. Cancellation never loses the dispatch intent or refunds a possible
execution. Azure's documented expiry and Analytics billing semantics are
unchanged. Low-level preflight still checks compiled policy, provider limits
and confidentiality on every attempt.

The branch/checkpoint store and case/query verifier validate attribution
before executing or reconstructing anything. V12 authenticates the plan,
approval if needed, all task holds, branch prefixes, issued query plans and
settlements, and the existing capture section. Reject double settlement,
branch confusion, a stale lease, missing approval, wildcard account scope,
swapped source or capture, and a reference to a future checkpoint. Offline
verification makes no network requests. Main and child allocation races
must fail closed after a crash or attempted duplicate invocation.

Tests cover two concurrent cloud children and the root contending for one
pool, exact 25%, one unit over, zero remaining, unknown usage after dispatch,
restart, partial or rejected provider results, precise row citation and
byte-stability with one and multiple workers and `preserve_order`. An
obedient model with the wrong type, absent assignment or wrong source receives
a typed denial and causes zero requests. No new credentials or production
dependencies are proposed for this block.
