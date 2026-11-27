# Local engine API and trusted approval contract

**Status.** Approved stdio transport, handshake and five case methods. The graphical
approval design has been selected by the analyst, and its implementation
contract is for review. Unix sockets and Windows named pipes require a
separate contract and native identity tests.

## Protocol

Use one `IRMIND-RPC-V1` and NUL prefix in each direction at connection start.
Each frame is a nonzero u32 big-endian length followed by exactly that many
UTF-8 bytes. Maximum 64 KiB, depth 16 and 4,096 nodes. Use J from the
[shared contract](v08-implementation-contracts.md). Read the length before
allocating. Truncation, unknown fields, duplicate keys or invalid frames
close the channel. Diagnostics go to bounded, sanitized stderr on stdio.
No free-form command strings.

Client request schema is `{id,method,params}`. IDs are positive u32 and
increase throughout a session. Before any other method, `hello` requires
`{version,client}`, version 1 and a 1–64 byte ASCII display label. Engine
replies with `{id,result,error}`, exactly one of result and error non-null.
The result for hello is `{version,session}`, with a random canonical UUID.
Error is `{code,message}`; fixed codes are 1 unsupported version, 2 invalid
request, 3 not admitted, 4 busy, 5 expired, 6 resync required and
7 cancelled. Messages are fixed and bounded, with no echo of supplied data.

Initial methods and exact params:

| Method | Params | Result |
| --- | --- | --- |
| `open_case` | `{case_id}` | `{case_id,anchor}` guarded session cursor; acquire existing case lock and authorize view. |
| `case_status` | `{case_id}` | Existing guarded local evidence status DTO, including case ID and exact cursor. |
| `subscribe` | `{case_id,after}` | `{cursor}`; stream committed engine projections after that sequence. |
| `start_turn` | `{case_id,text}` | `{operation}`; existing attended case turn validation, limit 8 KiB input. |
| `cancel` | `{case_id,operation}` | `{accepted}`; only the operation's admitted case and session. |

Case IDs are canonical UUIDs. The engine emits random operation UUIDs.
After, cursor and anchor
are nonnegative u64 stream sequences. The cursor binds the admitted case/session
and starts at 0. Reuse the engine's existing turn state and TUI actions.
One admitted case, one active turn and at most four pending requests per
session. Engine event is `{case_id,seq,kind,payload}` with a strictly
increasing seq, bounded validated projection and a closed discriminator
for case status, turn state, tool projection and approval state. Apply the
same guard and taint treatment as the TUI. Do not project raw keystore,
internal prompts, arbitrary ledger payloads, file paths or inaccessible
evidence. Keep at most 256 pending events and 1 MiB per session, with the
lower bound prevailing. On a gap, require an authenticated local status
refresh plus new subscription. A slow or disconnected client cannot hold
case locks or retain a reservation indefinitely. Use existing cancellation
and settlement for any in-flight operation.

## Approvals

The implemented V1 transport accepts only `hello` and the five methods
above. A tool requiring approval stays pending, with the decision taken
inside IRMind through the existing TUI at `/approvals`. The client receives
a guarded status notification.

The analyst chose approval from the GUI that launched IRMind over private
stdio. Review the [graphical approval contract](v08-graphical-approvals-contract.md)
for the proposed V2 methods, per-decision reauthentication, native
dependency review and threat model. Enable the extension only after
approval and native validation.
