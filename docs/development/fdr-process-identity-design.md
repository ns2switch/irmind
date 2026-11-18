# Falcon FDR process identity

Status: proposed contract; no implementation. [Español](../es/development/fdr-process-identity-design.md).

## Requirement and current boundary

FDR process/network correlation uses the provider's TargetProcessId and
ContextProcessId within an agent ID; ParentProcessId identifies the parent in the
same provider namespace. These are distinct from the operating-system PID.
CrowdStrike's [process/network example](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Combine%20ProcessRollup2%20and%20NetworkConnectIP4%20Events.md)
shows that join explicitly. Tenant `cid` must also separate identities.

The current domain accepts a process observation scoped to its source record or
to an explicitly represented process lifetime. It intentionally rejects generic
Host/Account scopes for processes. `process_lifetime` remains restricted to Sysmon
ProcessGuid in included mappings. Neither provider IDs nor PIDs, names or times
will be smuggled into that scope or into untyped compatibility identities.

## Proposed closed scope

Add `EntityIdentityScope::ProviderProcess { provider, tenant, host }` with a closed
provider enum containing only `CrowdStrikeFdr`. The entity value is the canonical
native provider process ID. Tenant and host are the explicit original `cid` and
`aid`, each bounded to the documented 32 hexadecimal bytes; preserve spelling,
without an implicit case-folding rule. Invalid/missing identity metadata remains
original data with a coverage diagnostic and cannot create a cross-record join.

Only process observations in `process.entity_id` (subject) or
`process.parent.entity_id` (parent) can use this scope. A PID observation cannot.
The stable comparison key is `(provider_process, provider, tenant, host, 0)`,
combined with the entity's native-ID value as today. The same ID in a different
provider, tenant, host or scope remains a different identity.

The app validates the scope against the original FDR SourceRecord: exact decoder
and format version, original cid/aid, and an allowed native ID field for the
record type. ProcessRollup2/SyntheticProcessRollup2 use TargetProcessId and
ParentProcessId; documented activity records use ContextProcessId. RawProcessId
continues to use source-record scope. Additional record/field combinations require
an explicit contract entry backed by source documentation.

Domain/export validation can check the closed scope, field, value and matching
host context. Without originals, authentication verifies the signed namespace
assertion; full reconstruction also reproduces it from the original SourceRecord
and exact decoder/mapping. No SourceRecord is reconstructed from normalized text.

## Finite interpreter additions

Add a closed `provider_process` scope to the current table interpreter, with
explicit provider, tenant and host paths. Compilation restricts its initial use to
`parser-fdr`, `fdr-source-v1`, the FDR format and approved original field paths.
Runtime validation also checks the actual original values, so a definition cannot
assign an OS PID or a timestamp to the provider namespace.

Add a bounded `u64_id` conversion for a decimal string or an integral native JSON
number. It accepts only decimal integers in 1..=u64::MAX, emits a canonical decimal
text value, and never evaluates an expression or uses floating point. Fractions,
exponents, negatives, zero, overflow and unsupported types retain original data
with a coverage diagnostic. They do not create a provider-scoped observation.

Classification, outcomes and role assignment stay in finite included TOML rules.
There is no new expression language, I/O, clock, network capability or global state.
The original fields and their lexical representation remain unchanged.

## Custody and format impact

This is a signed-format extension requiring a new scope variant and new golden
vectors. The ordered scope JSON is shown in [scope.json](fdr-process-vectors/scope.json),
with [SHA-256](fdr-process-vectors/scope.sha256) and [positive/negative cases](fdr-process-vectors/cases.json).
These are proposal vectors, not a claim that the runtime already accepts them.

The existing V3 columns already store the canonical scope descriptor; no Parquet
column, artifact envelope, seal or export section is added. Existing scope bytes
and current golden vectors stay unchanged; new scope bytes are covered by the
artifact hashes, mapping identity, reconstruction and export verification.
Record the extension in v0.5.5's format-impact note: older binaries cannot interpret
provider-scoped FDR observations. Do not consume case marker 5 or export V9, which
belong to the separately approved source-query contract.

The mapping hash binds both the rule definitions and the implemented scope and
conversion behavior. No historical mapping version is retained under the current
pre-1.0 policy. Installed definitions selecting an unsupported interpreter feature
remain disabled with a clear diagnostic rather than preventing startup.

## Acceptance tests

- Process TargetProcessId ↔ activity ContextProcessId and child ParentProcessId
  join only with the same cid/aid; equal IDs in different tenants/hosts do not.
- Reused OS PIDs and source-record/Sysmon/provider scopes remain distinct.
- Constructors reject provider scope on PID fields or non-process kinds; compiler
  and runtime reject other parsers, source versions, providers and native paths.
- Maximum u64, leading zeros, malformed values and missing metadata follow the
  conversion contract without falling back to a global/host/PID identity.
- Preserve original fields, provenance, taint, policy, scope ceilings, 32-observation
  limit, 1 MiB frames, query budgets and existing source/decoder limits.
- Check current and new golden bytes, preserve_order, 1/2/4/N worker equality,
  reconstruction, seal, export and a synthetic endpoint investigation.

## Alternative

Keep every FDR process observation in source-record scope and expose the native
IDs only as original searchable fields. This needs no scope extension, but cannot
provide the requested cross-record process graph correlation. It must be labelled
as partial coverage rather than claiming a complete process tree.
