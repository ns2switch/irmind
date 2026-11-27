# Child query attribution before publication

**Status.** Proposed amendment for review. The approved record bodies and V12
vectors are unchanged. This changes when the child binding becomes durable.

The root planner currently appends `SourceQueryPlanV1` before the analyst
reviews its preflight. `run_source_query_plan` can resolve any such plan ID
in the case. If a child wrote the same plan and appended
`irmind-child-source-query-v1` only when reserving the dispatch, there would
be a window in which `/source-query run` could treat that plan as a root
query. It could debit the root allocation or proceed after the child lease
expired. Queries with unknown estimates and those above the threshold need
a genuine analyst decision on the complete preflight, so publishing the
plan only when dispatching would also require a new approval interface.

## Proposed order

1. Commit and authenticate the child's branch proposal and checkpoint.
   Validate the active lease, exact query source, intersected scope and
   remaining share. Only then run the provider's normal preflight.
2. Under the case transaction, recheck the lease, adoption, scope, budget
   checkpoint and preflight revision. Append the existing `SourceQueryPlanV1`
   immediately followed by its `irmind-child-source-query-v1` binding in one
   batch. Publication is all-or-nothing. The binding names the plan content
   digest, case, child, proposal and checkpoint using the approved fields.
3. Classify execution origin from that authenticated pair. `/source-query run`
   can review and sign the existing `SourceQueryApprovalV1` for the exact
   child plan and preflight when required. It cannot execute the plan using
   the root allocation. Only the broker for the active child lease can request
   dispatch. An expired, detached or otherwise invalid child plan remains
   attributable and is not executable from any other route.
4. Inside the existing `append_source_query_dispatch` transaction, check the
   exact stored pair and the current lease and hold, then append the existing
   reservation, intent and dispatch audit with the installation-wide quota
   slot. No second binding, new wire field or port is needed. The provider
   receives its permit after that transaction commits.

This replaces the instruction to first append the binding with the reservation
at dispatch. The reservation still commits atomically with the dispatch intent
and quota. Earlier attribution closes publication of an unbound child plan.

## Regression tests

- Pause between publication and approval. A root request for the same plan
  ID cannot reach the provider. Confirming the reviewed plan alone still
  performs no dispatch.
- Crash between the two writes in the batch and check that neither row is
  visible. Crash after commit and before dispatch. The recovered child plan
  stays attributable and root dispatch is rejected.
- Cancel or expire the child after publication and after approval. Neither
  path can submit a provider execution. Retain existing hold policy for an
  uncertain execution that was already dispatched.
- A withheld or swapped binding, plan hash, checkpoint, scope or task fails
  replay. A coincidentally identical query separately planned by the root
  has its own plan ID and is subject to the root broker and policy.
- Simulated providers only. The approved empty V12 and receipt codec vectors
  reproduce unchanged. Tests exercise the authenticated case and branch with
  the real broker, not just the codec.
