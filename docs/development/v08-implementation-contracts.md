# v0.8 implementation contracts for review

[Español](../es/development/v08-implementation-contracts.md)

**Status.** The shared J encoding, record bodies, case marker 8, export V12
and the independent vectors are approved. The initial stdio API ships with
case 7/V11 and leaves decisions in the existing TUI. The
[graphical approval contract](v08-graphical-approvals-contract.md) replaces
the separate-TUI proposal and remains open for review. Source queries
from children follow the API. Enable MCP only on targets where native containment proves
all required denials. Hook implementation waits for review of the measured
native-versus-Wasm comparison on all five distribution targets. This follows the
[extensibility designs](https://github.com/ns2switch/irmind/pull/391) and the
[deferred source-query contract](source-queries-deferred.md).

1. [Signed local hooks](v08-hook-contract.md)
2. [Local MCP client](v08-mcp-contract.md)
3. [Local engine protocol](v08-engine-api-contract.md)
4. [Source queries in subagents](v08-child-source-query-contract.md)

## Shared local runtime boundary

Proposed optional application port:
`ConstrainedLocalRunner::launch(AdmittedLocalProgram, LocalIoPlan, Limits,
CancellationToken) -> LocalSession`. Its default returns unavailable.
`AdmittedLocalProgram` is engine-constructed from an authenticated global
admission. It carries executable and runtime identities and open handles to
the immutable verified files or snapshots. Nothing supplied by a model can
construct a program, environment, path or launch plan. `LocalIoPlan` admits only
protocol pipes, reviewed runtime inputs and private scratch. The engine owns
the deadlines and cancellation. The session exposes bounded framing and join.
Neither contract can use a general subprocess fallback.

The current EVTX isolation validates specific inherited-file workloads. It
does not establish the guarantees for a new interpreter or MCP server.
Each runtime configuration must independently prove denial of network,
unrelated files, child executables and external IPC, and cleanup of the
process tree. Bind authentication to the opened executable, runtime files
and data snapshot. No PATH search, dynamic server choice or inherited
credentials. A failed check disables that runtime. Apply the existing
ContentGuard and taint handling after byte bounds and before display or
model context.

## Shared signed wire proposal

Use existing Analyst and Agent keys and the existing signatures over global
operations and case entries. `J` is strict UTF-8 JSON with recursive UTF-8
key ordering, no extra whitespace, unambiguous integer values (u64 only),
standard minimal JSON string escaping, no duplicate or unknown fields, depth
at most 16, at most 4,096 nodes, and at most 256 KiB per body unless a smaller
limit below applies. Signed decoding re-encodes and compares. UUIDs use the
existing canonical case format. Hashes are exactly 64 lowercase hex digits.
Identifiers commit `SHA-256(ASCII(domain) || 00 || J(body))`. A new operation
or entry payload is `domain:hex(J(body))`. Its existing envelope signature
covers the exact payload. A digest is a commitment, not a permission.

The blocks that add signed records share **case marker 8 and export V12**.
Cases created by v0.8.0-alpha.1 use case 7 and V11. Keep the alpha binary to
open, verify or export those cases, or re-ingest the verified originals.
V12 starts with
`IRMIND-EXPORT-V12` and NUL, uses version 12 in the existing header layout
and carries the V11 sections in their established order, followed by a new
mandatory u64 big-endian count. That last section contains the reachable
hook and MCP admission/retirement proofs. Each object is u8 kind, 32 digest
bytes, u64 big-endian length and that many bytes. Kinds 0 and 1 respectively
denote hook and MCP operations. Object contents are compact JSON in the existing signed-operation member
order: case_id, seq, at, actor, operation, prev, hash, sig, public_key. The
operation string carries the canonical body above. Bind its audited
hash to the descriptor digest. Sort by (kind, digest) and reject duplicate,
missing, dangling, unrelated or trailing data. Authenticate the signing key
under the existing analyst trust for the case. The first contracts reference admissions only. Retirement stays in the
global store and takes effect for subsequent dispatch. An archive proves
the admissions referenced by the case, rather than the current global state. The count is always present, bounded
at 512. Limit each proof to 256 KiB and the combined section to 32 MiB, within
existing archive and framed-entry ceilings. Preserve seal bytes. The
[case-format classifier](case-7-export-v11-contract.md#central-rejection-and-upgrade)
rejects older formats up front and directs the analyst to the creating build.
No migration is proposed.

The engine protocol alone adds no signed case record and can ship against
case 7/V11 with decisions in the TUI. The protocol's version evolves
independently, including the proposed approval extension. Subagent query
bindings and plans use the existing audit, branch and capture sections
of the proposed V12.

## Order and acceptance

Integrate the engine API, source queries from subagents, MCP and hooks in
that order, each with its own matrix. Hooks and MCP share the runtime launch
boundary and each needs native isolation evidence on every enabled target.
Test the subagent query work with the existing three simulated providers.
Integrate signed changes at the single accepted case/export boundary.

Each block requires normal configuration and user documentation in English
and Spanish, cancellation and crash tests, and negative tests with the
obedient model. No live providers in CI. Transport authentication SDKs,
WebAssembly runtimes and new interpreter or network dependencies each require
their own approval. The [independent vectors](v08-implementation-vectors/README.md)
exercise the proposed encoding and bindings. They do not substitute for
tests against an authenticated case and native containment.
