# Interprocess coordination for interrupted-plan recovery

This is a port contract for exposing the existing reconciliation operation in the
TUI. It changes neither signed records nor reservations. No implementation is
included here. The original recovery interface proposal is [#316](https://github.com/ns2switch/irmind/pull/316).

## Required invariant

Recovery may reconcile durable interrupted work only when no process owns a live
preview or started plan for that case. An in-memory task registry describes one
process; confirmation text alone cannot establish this invariant. A process ID,
clock deadline or persisted flag is not a substitute for an operating-system lease.

Ordinary case reads remain possible. Recovery must not interrupt another session,
replay a request, release uncertain usage or authorize a replacement execution.

## Additive branch-store methods

Add these optional methods to `SubagentBranchStore`, using existing `CaseId`,
`CaseLock` and `AppError` types:

```rust
fn try_plan_activity(&self, case: &CaseId)
    -> Result<Box<dyn CaseLock>, AppError>;
fn try_plan_recovery(&self, case: &CaseId)
    -> Result<Box<dyn CaseLock>, AppError>;
```

Both default to an explicit unavailable error, never a no-op guard. Implementing
adapters and fakes must provide coordination before plan execution or recovery
is enabled. No existing method signature changes. No new production dependency
is needed: the local adapter uses the existing `fs4` primitives.

`try_plan_activity` obtains a shared per-case activity lease.
`try_plan_recovery` obtains an exclusive lease on the same gate. Acquisition is
nonblocking; contention or unsupported locking fails closed with an actionable
error. The gate is distinct from the short repository transaction lock and the
existing deletion/session lock, so reconciliation can append its normal signed
transactions without acquiring a shared lock underneath its own exclusive lock.

## Lifetimes and ordering

1. Retain the existing case-session protection against deletion when available.
2. Acquire the activity gate before publishing any plan or preview reservation.
3. Acquire the ordinary repository transaction lock only for existing transactions.

A private owned lease travels with the prepared/started plan, not in a signed
record. All running workers retain ownership until they are canceled and joined;
a root handle disappearing cannot release the gate while a child still runs.
The activity lease ends only after the existing terminal/release transactions
and worker joins. Dropping a preview follows its existing signed-expiration path.
An abrupt process exit releases its OS lease without inventing a terminal record.

`Engine::cancel_interrupted_subagent_plans` itself acquires the exclusive gate,
before enumerating or reconciling plans, and retains it through the entire
operation. Checking only in the TUI is insufficient. The existing local-live-task
check remains an additional check. While recovery holds the gate, another process
cannot publish a new preview or start a plan.

## TUI and retained semantics

The Analyst confirms recovery explicitly, with Cancel selected initially. A busy
gate explains that the plan must be finished/canceled in its owning session.
There is no force option, timeout-based override or model tool for recovery.
Sealed cases remain immutable. Completed branches, committed prefixes, uncertain
usage, single settlement, scope and all existing limits retain their semantics.

No case marker, audit encoding, seal, export V8, golden bytes or migration changes.
The new ownership fields are runtime values only.

## Native regression criteria

Use independent processes and bounded event synchronization on Linux, macOS and
Windows; two objects sharing one process are not sufficient evidence.

- A live preview or started child in process A makes recovery in B fail without
  appending recovery records, canceling the child or releasing its reservation.
- A recovery gate in B prevents a new plan in A before any hold is signed or model
  request starts. Concurrent recovery is rejected; subsequent recovery is idempotent.
- A child keeps its lease after a root handle is dropped until that worker joins.
- Killing A releases the OS lease. B then reconciles the authenticated prefix,
  retains unknown provider usage and never replays a provider/tool call.
- Case deletion remains blocked throughout live activity/recovery; ordinary reads
  and short signed transactions keep working without lock-order deadlocks.
- Missing coordination adapters, lock errors and unavailable locking reject the
  operation; a fake obedient model cannot invoke or override recovery.
