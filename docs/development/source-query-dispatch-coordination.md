# Source query dispatch coordination

A deployment can use one provider account, project or workspace from several
cases and processes. Its source frequency and concurrency limits apply across
those sessions. Keep the first release within the existing V5 case and V9 export
formats. The signed case receipts continue to account for each acquisition.

## Proposed storage contract

Add an optional `AuditLog::append_source_query_dispatch` operation. It receives
the complete signed reservation and submit-intent batch, the final ordinary
tool-call receipt, and a validated dispatch quota. The case log and global audit already share the installation's `irmind.db`.
The installation-wide quota table lives in that same SQLite database and WAL.
The adapter starts `BEGIN IMMEDIATE`, checks and inserts the quota slot, then
appends the complete case batch. Both become visible at one commit
(`synchronous=FULL`). There is no `ATTACH` or second database. An adapter without
this operation reports source dispatch as unavailable.

The quota key is the closed provider module, owner and location from the signed
plan. Giving the same resource a second source ID does not create another quota.
The application checks the signed adoption, authorized request and case budget
before invoking storage. Storage serializes competing dispatches across cases
and processes. The durable index tracks receipt identities, the rolling
60-second window and live reservations. It does not authorize a query.

A normal terminal settlement releases its live slot in the transaction that
appends its signed receipt. The same rule applies to the approved Azure expiry
recovery. Ambiguous executions keep their slots. The quota table has no
cascading case foreign key, so deletion preserves the rolling window and any
unresolved slot. On startup, the adapter checks the index against dispatch
receipts in both directions. An inconsistent inventory disables dispatch and
preserves access to the case audit.

Preflight checks the ordinary tool-call budget and uses bounded provider
requests. A preflight result grants no execution lease. The operation and indexes above stay local to the
installation. Case receipts and export verification continue to use the approved
signed fields and golden bytes.

## Verification

Use two cases with the same provider resource and two independent processes.
With concurrency one, the second submit reaches the fake provider only after a
known settlement. Verify a distinct resource still proceeds. Test a rolling
window across reopen and case deletion, an uncertain execution, the Azure expiry
path, a failed database append and an adapter without coordination support.
Each rejection must occur before the fake provider observes a new submission.
A subprocess exits with the WAL transaction open after the quota write and
before the case batch. A second test stages the case batch first exclusively
for fault injection and exits before writing the quota. Reopening must yield
neither half in either test. Independently committed halves injected by a
storage fixture must each disable dispatch.
