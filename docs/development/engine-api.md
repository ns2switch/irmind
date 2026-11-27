# Local engine API

[Español](../es/development/engine-api.md)

`irmind serve <case_uuid>` exposes one case to one local client. The client
launches the installed IRMind executable with separate stdin and stdout pipes
while preserving the analyst's controlling terminal. IRMind displays the case
UUID on that terminal and asks the analyst to type it to admit the session.
File keystore input stays on the IRMind terminal. `--passphrase-fd` is rejected
in this mode. Use the existing approved model configuration for turns.
Existing subagent branches are verified with the case. Start new delegation
plans from the TUI, where the analyst can review the reserved resources.

## Wire

Both sides start with `IRMIND-RPC-V1` and a NUL byte. Each frame is a nonzero
u32 big-endian length followed by that many bytes of UTF-8 JSON. Sort every
object's keys by UTF-8 bytes; encode compactly with minimal escapes and use
nonnegative integer numbers no wider than u64. Limits are 64 KiB per frame,
16 levels and 4,096 nodes. Duplicate keys, unknown fields, noncanonical JSON,
truncated frames and unsupported methods close the session. Use a positive
u32 ID that increases on every request. The first method is `hello` with
`{"client":"my-local-client","version":1}`. It returns the session UUID.

Requests use `{id,method,params}`. Replies use `{id,result,error}` with
exactly one of `result` and `error` non-null. Errors have numeric `code`
and fixed `message`. The admitted case UUID must be present in every
subsequent request as `case_id`.

| Method | Other parameters | Result |
| --- | --- | --- |
| `open_case` | None | `case_id`, `anchor` (0). Verifies custody and takes a case session lease. |
| `case_status` | None | `case_id`, `cursor`, `sealed`, `evidence`. The evidence object contains counts of signed sources, local blobs, decoder rejections, folder outcomes and integrity comparisons. `indexed_summary` contains event counts and time bounds when available. Returns busy when a turn is active. |
| `subscribe` | `after` | `cursor`. Use the cursor from this session's preceding `open_case`, `case_status` or last event. |
| `start_turn` | `text` | `operation`, a UUID. At most 8 KiB of input and one active turn. Policy and normal engine budgets apply. |
| `cancel` | `operation` | `accepted`. Only the active operation in this session can be cancelled. |

Events use `{case_id,seq,kind,payload}`. `seq` refers to the authenticated
case chain. Event kinds are `case_status`, `turn_state`, `tool_projection`
and `approval_state`. The payload carries a closed `state`. A final answer
adds guarded `text` and `clipped` for previews beyond 8 KiB. Read answers
in full in IRMind. The signed answer keeps the existing security limits.
The API publishes projections of committed state, not live provider chunks
or raw tool results, approval arguments, arbitrary file paths or keys.
Clients render returned text as untrusted plain text.

The server holds at most 256 pending events and 1 MiB of event frames. On
`resync_required`, fetch `case_status` and subscribe from its fresh cursor.
Fetching `case_status` replaces the previous cursor and ends its subscription.
Keep reading output while requesting or cancelling a turn. A writer that
cannot drain, client EOF and shutdown cancel the active turn through the
engine. Idle sessions expire after two minutes; ongoing turns use the
engine's own cancellation and budget controls.

## Approvals

When V1 signals `review_in_tui`, open the case in IRMind's TUI and
use `/approvals`. IRMind signs there under the existing policy and key
controls. The client can observe a guarded state only. V1 has no approval, prompt-presentation, signing, credential or configuration
operation. This implementation uses case format 8 and export V12.

## Graphical approval sessions

A trusted graphical client can choose RPC V2 with
`irmind serve <case_uuid> --protocol-version 2`. Use private inherited
pipes, the `IRMIND-RPC-V2` magic and a V2 hello. IRMind still asks for
local case admission at startup. V1 is the default.

The GUI shows the full request from IRMind as escaped plain text. Review
the action, case, arguments, effective scope, decision, expiry and code.
V2 with an encrypted file keystore verifies the Analyst passphrase for
each submitted decision. The GUI can see what you type. Use a graphical
client you trust with that phrase. Close the session before switching to
the TUI if the session owns the file-keystore lock.

With the system keystore, use `/approvals` in the IRMind TUI. Interactive
validation of Windows Hello and Touch ID is scheduled for after v0.8.
