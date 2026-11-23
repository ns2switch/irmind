# v0.8 extensibility designs

**Status.** Design accepted for v0.8. Each implementation contract requires
explicit approval, including any new signed bytes, production dependencies
or credentials.

## Signed local hooks

The organization decides whether hooks may run and sets the executable,
case-scope and resource constraints. An analyst signs a local admission
record naming the executable and script SHA-256, pinned interpreter and
configuration, phase, tool selector, input and output schema, and ceilings.
Activation and retirement are auditable. A modified script, interpreter or
manifest requires a new admission. Approve an immutable verified copy for
execution and bind the launched handles to that copy.

- A before hook receives an already validated, minimal typed summary for
  an admitted tool proposal. It may advise or veto. It cannot change the
  tool, arguments, approved action digest, policy decision, approval
  requirement, or any budget. Invoke it after argument and scope validation
  but before the final dispatch. A required hook error or timeout vetoes the
  dispatch and remains visible. An optional observer has advice-only powers.
- An after hook receives bounded status and approved public metadata after
  execution. It may annotate the display or audit outcome. It cannot rewrite
  tool results, origin, trust or the case ledger and cannot initiate another
  tool or hook. Existing tool result custody and settlement remain in force.
- A status-bar script is separate, disabled until specifically admitted.
  It sees only approved status values from the declarative segment list.
  It emits a bounded plain-text segment, has no launch-on-keystroke mode,
  and follows the normal status-bar width, escaping, and NO_COLOR behavior.

Launch a reviewed runtime with a fixed argument vector, no shell expansion or
PATH lookup, an allowlisted environment, only protocol handles inherited, and
a private working directory. Isolation denies networking, unrelated paths,
child executables and external IPC. The runtime can read the allowlisted
interpreter and admitted script, and writes only to its private scratch if
required. Verify the confinement for the specific runtime on each platform
before offering the feature. Inadequate confinement makes hooks
unavailable on that platform. Bound wall time, bytes, descendants, memory,
concurrency and retries. A status segment starts with a 256-byte display
limit and a two-second minimum refresh interval. Process cleanup covers
timeouts, crashes, cancellation and case closure.

Threats include changes after admission, an interpreter loading extra code,
environment or handle reuse, filesystem and network disclosure, status-bar
terminal injection, and a compliant model trying to approve or bypass a
hook. Hash the launch inputs, suppress implicit startup files, enforce
containment independently of script promises, and run input/output through
existing taint and terminal sanitization. Log admitted identity, proposal
binding, phase and outcome with bounded diagnostics. Review the signed
admission and case receipt formats separately. Use native negative tests for
permissions, data access, child cleanup and substituted artifacts.

### WebAssembly alternative

Compare a guest runtime such as Wasmtime with the native-interpreter
helper. A WebAssembly guest would receive only reviewed, bounded host
imports for request and response bytes. Omit WASI, filesystem, network,
clock, environment and process imports. Set linear-memory and table limits,
fuel and a wall-clock deadline. Keep the runtime in a killable helper so
host defects and stalled imports have an independent containment boundary.
Require the same immutable artifact hash, audit semantics and negative tests.
Native interpreters retain existing script compatibility and can reuse a
smaller launcher, with three OS-specific confinement and validation paths.
WebAssembly would require guest-language tooling and a new runtime and may add
substantially to the release size if a compiler backend ships. Compare
stripped helper size, locked production dependencies, cold launch latency
and peak RSS on all release targets, including a reduced runtime build.
This is an option to evaluate in v0.8. [Wasmtime security model](https://docs.wasmtime.dev/security.html) ·
[Wasmtime execution limits](https://docs.wasmtime.dev/examples-interrupting-wasm.html)

## Optional MCP client

The proposed first surface is explicitly admitted local stdio servers and a
bounded tool-call subset of MCP revision `2025-11-25`. IRMind starts the
server under the same verified isolation class as local hooks. No servers
or tools are discovered or enabled by default. Design Streamable HTTP
separately, with approved endpoint allowlists, TLS validation, explicit
tenant/account bounds, and a dedicated credential and audience contract.
No automatic discovery, redirection, or credential forwarding is part of
the initial surface. Require that exact version in the initialization
reply and close the session on a different revision. [Published MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) ·
[Published MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

Admit the server executable digest and each exact namespaced tool schema,
argument limits, capabilities, declared risk and pinned description. A
server announcement and its annotation are untrusted claims. An analyst
sets the minimum IRMind risk and policy applies the strictest applicable
classification. Reject ambiguous side effects, arbitrary command dispatch,
unbounded arguments or scope declarations the broker cannot enforce.
Keep v0.8's first local tools read-only and case-scoped. A changed schema,
tool list or executable requires fresh admission. The model sees only
admitted, guarded tool descriptors. It proposes typed arguments without
choosing an endpoint, credentials, scopes, or tool classification.

Every call goes through the same case scope intersection, policy, analyst
approval where required, and case budgets. Bind approvals to tool ID,
server and schema hashes, actual arguments and destinations. Broker input
explicitly; no ambient roots, workdir, home directory or credentials. The
server only receives case data explicitly permitted for that call. Raw and
structured output are untrusted, size-limited and passed through ContentGuard
before any model or display use. Unknown response types, unsupported protocol
methods, reverse requests for sampling or user input, callbacks, resource
fetches and installation requests are rejected. A tool response cannot cause
a credential grant, approval or new dispatch.

| Threat | Control and test |
| --- | --- |
| Tool spoofing, list churn, risk downgrade, mutable executable | Freeze admitted identities and schemas, compare canonical descriptors, and reject a change. Exercise duplicate names, config swaps, and false read-only hints. |
| Instruction injection in metadata, result text and structured fields | Apply ContentGuard and taint end to end. Run hostile metadata and results through the obedient model fixture. Constrain output coordinates, size and text handling. |
| Case or tenant scope confusion, local file access, credential exposure | Validate case scope per request, use immutable argument schema, separate credential domains and verify process confinement. Use synthetic case boundary and disclosure rejection tests. |
| Unexpected reverse traffic or unauthenticated transition | Strict protocol revision and state machine, unique request IDs, rejecting unsupported methods. Verify no tool or approval can be triggered by server-originated text. |
| Network and transport risks for a future HTTP client | Explicit endpoint registration, exact origin and redirects denied, destination and address bounds throughout the connection, service-scoped auth and no token passthrough. Use only simulated servers for tests. |
| Resource exhaustion and replay after interruption | Bound pending requests, frame depth and bytes, settle the actual case budget, time out and kill the process tree, and avoid ambiguous retries. Test stalled and oversized streams and stale request IDs. |

Keep launch and protocol telemetry local and bounded. A signed receipt binds
server identity, tool, decision, request, result and cost without publicizing
secrets. Distinguish analyzing a response already retained in a case from
replaying an external call. Review any new record layout and archive limits.
Reuse the existing bounded serialization and containment infrastructure
where supported. Each SDK or credential path is a separate decision.

## Versioned engine API

`serve` initially exposes a local protocol only. Default to a single
stdio peer created by an explicit launch. Optional Unix sockets and Windows
named pipes are local, same-user and explicitly configured. On Unix use a
private parent directory, a private socket and peer credentials. On Windows
use a current-user pipe ACL, reject remote pipe clients and validate peer
identity. Avoid following stale socket paths or publishing an unsafe endpoint.
There is no default TCP listener.

Use a versioned, length-delimited message format with explicit schema
negotiation, bounded frames and strict request validation. An unsupported
version returns a clear error. Requests carry an ID, case scope and typed
operation. Responses echo the ID. Stream ordered engine events with sequence
numbers, cancellation and bounded backpressure. A missed event causes an
explicit resync from an authenticated sequence, rather than silently
inventing a view. A disconnected client cannot leave an unbounded operation
or orphan reservation. The engine remains the only owner of case locks,
budget settlement, custody state and privileged local paths.

An external client can show a pending operation and ask IRMind to open a
trusted approval prompt. IRMind presents the exact case, tool, arguments,
scope, expiry and a request code in an IRMind-owned terminal or native
prompt. The analyst checks the request code displayed by the separate GUI
and confirms inside IRMind. Approval unlocks the keystore with the
passphrase entered directly into IRMind or uses OS authentication through
IRMind, such as Touch ID on macOS or Windows Hello on Windows. OS
authentication proves local presence and authorizes the exact one-use
challenge inside IRMind. It does not give the GUI a key or an approval
token. The server checks the outstanding action again and signs the exact
challenge through the keystore. With no trusted prompt the action remains
pending or expires.

The GUI displays waiting, approved, denied or expired status from the engine.
A click in the GUI may request a prompt. IPC has no approval or signature
operation. Private keys, passphrases and OS authentication assertions remain
inside IRMind. A versioned approval contract must include substituted-action
and replay tests. Stdio reserves stdout for frames and uses only guarded
diagnostics on stderr.

Test cross-user denial, counterfeit approvals, replay and races on a case
lock, mismatched IDs and protocol versions, oversized or truncated frames,
slow readers, cancellation, and malicious evidence received through IPC.
Use a mock client and the existing synthetic Windows/AWS/Kubernetes
investigation to validate parity with the TUI's event stream and signed
custody. The implementation contract must specify the exact framing, port
surface, authentication assertions and versioned golden examples. Scope,
credentials and signed format decisions remain separate from these designs.
