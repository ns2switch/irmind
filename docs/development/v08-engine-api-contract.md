# Local engine API and trusted approval contract

**Status.** Approved stdio transport, handshake and five case methods. The
local approval presentation described below still requires review. Unix
sockets and Windows named pipes can follow after their native identity tests.
TCP is outside this contract.

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

## Local approval surface for review

The first stdio implementation accepts only `hello` and the five methods
above. A tool requiring approval remains pending under the usual custody
rules. The client tells the analyst to open the matching case in the IRMind
TUI and review the request there. The client cannot request a prompt, see
approval arguments or submit a decision over the protocol.

For the follow-up, use a separate IRMind TUI in a terminal launched by the
analyst. The graphical client opens a local instructions panel. It shows the
case UUID and confirmation code and offers to copy `irmind tui <case_uuid>`.
Only the canonical UUID is substituted. The terminal and installed IRMind
executable are selected by the analyst. The client never runs a shell command,
types into a terminal or forwards the copied code as confirmation.

| Platform | Trusted surface and opening sequence |
| --- | --- |
| Linux | The analyst opens their usual desktop terminal or an existing local TTY, runs `irmind tui <case_uuid>` and opens `/approvals`. No dependency on a desktop portal or terminal emulator API. |
| macOS | The analyst opens Terminal.app from Applications or Spotlight, runs `irmind tui <case_uuid>` and opens `/approvals`. No AppleScript, terminal injection, or native plug-in. |
| Windows | The analyst opens Windows Terminal from Start, runs `irmind tui <case_uuid>` in PowerShell and opens `/approvals`. No Windows Hello, console injection or client-controlled credential dialog. |

The TUI verifies the case and acquires the existing case and operation
locks. A client-started turn commits the pending request and yields before
an approval is reviewed. The approval is signed by the local IRMind process
using the existing Analyst key and audit records. If the client is slow,
closed or no longer owns the presentation lease, the TUI still uses its
normal approval workflow and the pending signed record. The GUI receives
only a guarded state change. Deliberate denial or disconnect cannot be
turned into approval by the client.

In a separately approved revision, `request_approval_prompt` can register
one pending presentation and `approval_status` can read its guarded state.
The proposed `LocalApprovalPresenter` exposes presentation status only.
Default unavailable leaves decisions pending until expiry. The IPC interface
contains no approve, sign, unlock or import-credentials method. The IRMind
TUI shows the exact action, case, arguments, effective scope, expiry and
matching code before local confirmation. Passphrase entry happens inside
IRMind. A native Touch ID or Windows Hello path needs a separate decision.
Peer credentials and a matching code alone grant no authority.

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
