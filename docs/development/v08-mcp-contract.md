# Local MCP tool admission and protocol contract

**Status.** Proposed implementation. The first version is read-only,
case-scoped and disabled by default. See the
[shared runtime and custody rules](v08-implementation-contracts.md).

## Transport and descriptor

Use local stdio under `ConstrainedLocalRunner`. Pin revision `2025-11-25`.
Send `initialize` with empty client capabilities. Require the exact revision
and `tools` from the server, then send `notifications/initialized`. Reject
server instructions as authority. Admit at most one server session at a
time per case, no more than 16 tools per server and one in-flight request. After initialization the host sends one
`tools/list` request before any `tools/call`.
Use UTF-8 JSON-RPC 2.0 with LF-delimited messages. Bound a frame at 64 KiB,
depth 16 and 4,096 nodes before dispatch. Use increasing positive u32 request
IDs. End the session on overflow, unknown/duplicate IDs, malformed framing,
unexpected methods, batch, unsupported capability transitions or tool-list
change. Tool enumeration is part of attended admission. Accept one bounded
unpaginated response initially; a cursor or further pages prevent admission
in this version. No automatic discovery or new launch after an ambiguous
failure. The maximum call deadline is 10 s or the earlier case/tool bound.
Discard stderr except a bounded, escaped local diagnostic summary.
[Lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) ·
[Stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) ·
[Tool messages](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

As proposed, `McpAdmissionStore` loads the exact authenticated metadata, and
`ConstrainedLocalRunner` owns the process. The analyst admits one registered
server and tool set before any case call. The signed
`irmind-mcp-admission-v1` body is
`{version,id,program,runtime,protocol,policy,tools}`. Each tool is
`{name,descriptor,projection,risk}` in ASCII name order, unique.
`descriptor` commits the canonical reviewed tool name, description and
schema. `projection` commits a closed host-side argument/result projection
for typed, case-authorized data. Tool IDs in IRMind include the admission
ID and exact tool name. The risk field is 0 for Read in v0.8. The server's
annotations cannot choose the risk. The runtime pins both the approved
executable identity and the no-egress profile. Retirement is an Analyst
`irmind-mcp-retirement-v1` body `{version,admission,reason}`, with the
same reason bound as hooks.

The supported input schema is one closed object with at most 16 fields.
Properties are bounded strings, booleans or bounded nonnegative integers.
Use `additionalProperties:false`, exact types, explicit required-field
names and the lower of the approved schema and existing tool bounds. Only
registered projections may access case data. The first projection accepts
authorized exact source/row references and their approved fields from the
case. No path, endpoint, command or arbitrary evidence attachment can be
supplied. Validate the exact effective tool list and canonical descriptors
when opening a session. Revalidate the selected source scope and approved
arguments immediately before sending `tools/call`. A runtime response can
provide only bounded text or a bounded registered structured result. It is
untrusted and must pass ContentGuard. Reject binary content, resource links
and reverse requests. Exclude Streamable HTTP, endpoint configuration and
credentials from this implementation.

## Policy and signed effects

Use the existing tool proposal, policy, one dispatch debit and result
commitments. Enforce the ceiling, case scope, per-call broker and any
required Analyst approval before forwarding approved values to the server.
Bind the approval to the exact case, tool, approved argument digest,
projection, policy and admission digest. The Agent signs an
`irmind-mcp-call-v1` body
`{version,case_id,admission,call_id,tool,proposal,dispatch,result,outcome}`
after the dispatch and result commitments. Bind dispatch and result to the
earlier authenticated case entries. Outcome codes are 0 complete, 1 denied
by the server, 2 protocol failure, 3 timeout, and 4 cancelled. For a
dispatched call without materialized result, `result` is null. Failed
admission or policy never sends a call and uses the ordinary denial path.
After ambiguity, keep the accounted dispatch and close the session. Export
the referenced admission proof with the normal guarded tool evidence.
Third-party verification authenticates the committed result and policy
history locally, without reconnecting to the server.

Test exact-version failure, unadmitted or changed descriptors, fake read-only
annotations, malformed and oversized frames, delayed/duplicate response IDs,
reverse requests, unsigned descriptors, and cross-case source attempts.
Use a synthetic tool and an obedient model for end-to-end proof that tool
output cannot grant permission or start a second action.
