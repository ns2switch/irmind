# Source query dispatch coordination

A deployment can use one provider account, project or workspace from several
cases and processes. Its source frequency and concurrency limits apply across
those sessions. Keep the first release within the existing V5 case and V9 export
formats. The signed case receipts continue to account for each acquisition.

## Proposed storage contract

Add an optional `AuditLog::append_source_query_dispatch` operation. It receives
the complete signed reservation and submit-intent batch, the final ordinary
tool-call receipt, and a validated dispatch quota. The implementation that owns
the case log checks the quota and appends the batch in one database transaction.
An adapter without this operation reports source dispatch as unavailable.

The quota key is the closed provider module, owner and location from the signed
plan. Giving the same resource a second source ID does not create another quota.
The application checks the signed adoption, authorized request and case budget
before invoking storage. Storage serializes competing dispatches across cases
and processes. The durable index tracks receipt identities, the rolling
60-second window and live reservations. It does not authorize a query.

A normal terminal settlement releases its live slot. The existing signed Azure
expiry recovery only releases the Azure slot under the approved conditions.
Ambiguous executions keep their slots. A case deletion cannot erase a recent
submission from the frequency window. Startup checks the local index against
the receipts needed for admission and blocks dispatch if that state is uncertain.

Preflight runs under the normal tool-call and provider request limits. It cannot
grant a paid execution lease. The operation and indexes above stay local to the
installation. Case receipts and export verification continue to use the approved
signed fields and golden bytes.

## Verification

Use two cases with the same provider resource and two independent processes.
With concurrency one, the second submit reaches the fake provider only after a
known settlement. Verify a distinct resource still proceeds. Test a rolling
window across reopen and case deletion, an uncertain execution, the Azure expiry
path, a failed database append and an adapter without coordination support.
Each rejection must occur before the fake provider observes a new submission.
