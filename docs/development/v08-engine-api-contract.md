# Local engine API and trusted approval contract

**Status.** Proposed implementation. The first transport is stdio by explicit
launch. Unix sockets and Windows named pipes can follow after their native
identity tests. TCP is outside this contract.

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
| `request_approval_prompt` | `{case_id,proposal}` | `{request,code,expires_in_ms}`; request the trusted prompt for a pending authenticated audit digest. |
| `approval_status` | `{case_id,request}` | `{state}`; pending, approved, denied or expired from the engine. |

Case IDs are canonical UUIDs. Operation and request are random UUIDs emitted by
the engine. Proposal is an authenticated case digest. After, cursor and anchor
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

## Local trust path

Proposed application port `LocalApprovalPresenter` opens a trusted local
IRMind surface for a pending request and exposes only its presentation
status to the engine adapter. Default unavailable leaves decisions pending
until expiry. The IPC interface contains no approve, sign, unlock or import
credentials method. A local UI handles confirmation and creates the existing
signed Analyst decision in-process. It displays the exact action, case,
arguments, effective scope, expiry and a human-comparable code. The GUI
displays the same waiting code; a click may request the prompt. The analyst
enters the passphrase directly in IRMind. A future native Touch ID/Windows
Hello path requires platform decisions and explicit dependency approval.
Peer credentials and a matching code alone are insufficient for approval.

Each request is single-use, tied to one authenticated pending proposal,
case, local session and fresh 32-byte random engine nonce. The displayed
code is the first 16 lowercase hex characters of
`SHA-256("irmind-local-approval-v1" || 00 || J({case_id,session,proposal,nonce}))`,
grouped every four characters. The code is a cross-check, with no authority.
Expiry is the earlier of the proposal deadline and 60 s measured by the
engine. A local confirmation rechecks authorization, bound arguments and
active proposal under the case lock. On process restart all pending
presentations expire. Only the existing signed approval record commits a
decision. This adds no signed format or export dependency.

A launch with stdio admits the initiating local analyst explicitly and
keeps the approval surface separate from protocol pipes. For sockets
verify Unix private directory/socket permissions and peer UID. For a pipe
use a current-user DACL, reject remote clients and check the peer SID
before case operations. No TCP listener, forwarded credentials or
unattended scope grant. Run cross-user and stale endpoint tests before
enabling either native transport.

Tests cover handshake version and length, out-of-order IDs, unexpected
methods (including fabricated approvals), two competing clients, stale
case anchors, cancellation, a substituted action, lease expiry, keyboard
input via the trusted local prompt and a slow IPC reader. A local mock GUI
must reproduce the guarded Windows/AWS/Kubernetes TUI event sequence.
