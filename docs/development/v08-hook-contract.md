# Local hook admission and execution contract

**Status.** Format approved. Implementation awaits review of the measured
native-interpreter and Wasm comparison. See the
[shared runtime and custody rules](v08-implementation-contracts.md).

## Admission and ports

An Analyst-owned action admits one execution profile. The
`irmind-hook-admission-v1` body is
`{version,id,program,runtime,configuration,mode,tools,policy,max_input_bytes,max_output_bytes,timeout_ms}`.
Version is 1. ID is a UUID. Program is the SHA-256 of the exact immutable
guest or script. Runtime is the digest of the approved launch recipe, including
platform runtime files and isolation profile. Configuration and policy are
digests of authenticated snapshots. Mode is 0 required before, 1 advice-only
before, 2 after, or 3 status bar. Tools are sorted unique registered tool
identifiers, at most 32. Modes 0–2 require a nonempty list. Mode 3 carries
an empty list and a closed allowed status-field set in its reviewed
configuration. A separate Analyst operation
`irmind-hook-retirement-v1` has body `{version,admission,reason}`.
It retires that exact audit hash. Reason is a plain text analyst label
bounded to 128 bytes.

`HookAdmissionStore` resolves the current, authenticated admission by digest.
`ConstrainedLocalRunner` runs it with a closed, engine-owned I/O plan.
Both ports are optional and fail closed for configured required hooks.
A missing optional hook is reported locally; absence of an installed hook
keeps the existing unmodified tool path.

The first candidate is a single process per invocation with a length-prefixed
request and response over inherited pipes. Each message uses u32 big-endian
length followed by J and exactly one response then EOF. Proposal message
`{version,invocation,phase,tool,action,fields}` carries invocation UUID,
phase code, the validated tool and proposal digest, and the minimal approved
projection of fields. Before phases do not receive the evidence body. After
receives safe status and public metadata, without raw tool output. Status
bar uses an empty tool string, a zero action digest and the admitted status
values. Response `{version,invocation,decision,text}` has decision 0 pass,
1 advice or 2 veto, and escaped, guarded plain text. Only mode 0 may veto.
Unsupported semantics, an unexpected ID, duplicate response or malformed
output fail that invocation. Frames cap input at 16 KiB and output at 4 KiB.
A status-bar response is at most 256 display bytes with minimum refresh
interval 2 s. Default wall time 1 s, compiled maximum 5 s, one active
invocation per case, and a bounded launch pool. The runtime profile fixes
memory and scratch ceilings before admission. No retry after launch.

## Dispatch and custody

Resolve tool arguments and scopes first, then apply policy. Required before
hooks run after any required analyst approval and immediately before the
engine's last admission check and dispatch. Their allowance cannot revalidate,
rewrite or approve the tool. Snapshot the admitted hooks per action, in
admission-hash order. Recheck activation, exact action and budgets before
dispatch. Timeout, malformed response, veto or unavailable required runtime
blocks dispatch. After hooks observe settled status and cannot affect custody
or cause a new call. A status-bar script is separately admitted, is never
invoked by a keystroke and remains subject to terminal width and escaping.

`irmind-hook-invocation-v1` is an Agent case entry with body
`{version,case_id,invocation,admission,phase,tool_action,outcome,input,result}`.
`admission` is the global audit hash. `tool_action` is the earlier validated
proposal digest, or the zero digest for the status bar. `input` commits the
bounded request bytes and `result` the bounded guarded response bytes, or
null when absent. Status codes are 0 passed, 1 advised, 2 vetoed, 3 timed out,
4 unavailable, 5 invalid response, 6 cancelled. A case-linked advisory is
recorded before displaying its admitted effect. Outside a case, the status
bar displays only standard segments in v0.8. Within a case, cap script
evaluations at the lower of policy and 256 per case. Reuse the last committed
segment between evaluations. A required before receipt must precede its
dispatch. Export contains the signed admission proof and invocation receipt;
an offline verifier authenticates the commitments without launching programs.

## Runtime decision and tests

Compare a constrained native interpreter with a Wasm guest in a separate
helper. For Wasm, expose only bounded guest input/output, with no WASI and
no filesystem, clock, network or process imports. Set memory, table, fuel
and wall-clock limits. Keep outer process containment on both paths. No Wasm
dependency is included in this contract. Measure stripped helper size, lockfile
closure, latency, RSS and native containment on five targets before selecting a runtime. If
native isolation, including interpreter startup files and libraries, cannot
be demonstrated on a platform, hooks stay unavailable there.
[Wasmtime security model](https://docs.wasmtime.dev/security.html).

Test hash substitution at launch, timeouts, tree cleanup, input minimization,
unavailable required hooks, altered approvals and raw terminal escape codes.
For each enabled native platform test the isolation boundaries. Exercise
a required veto with zero dispatches, an advice-only veto response, and a
status-bar request that cannot issue a tool or change an approval.
