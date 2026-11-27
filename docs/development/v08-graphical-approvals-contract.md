# Graphical approvals over the local engine API

[Español](../es/development/v08-graphical-approvals-contract.md)

**Status.** The analyst selected approval in the launching GUI on 2026-11-27.
This wire protocol, threat model and dependency proposal are for review.
Today, decisions remain in the IRMind TUI under `/approvals`.

## Scope and trust boundary

One GUI starts the installed `irmind serve <case_uuid>` directly with private
stdin and stdout pipes and completes the existing local admission. On POSIX
close unused ends and mark the other descriptors close-on-exec. On Windows
restrict inheritance to the intended handles for that child. No shared log,
PTY transcript, proxy, shell or developer-tools bridge may carry protocol
frames. A successful admission authorizes one case view. Per-decision
reauthentication is still required. The security boundary is the admitted
process and its pipes, with the OS enforcing their ownership. The client
label and parent PID provide no identity proof. This revision is stdio only.
Unix sockets and Windows named pipes need their own contract.

The GUI shows the exact action, case UUID, named arguments, current effective
scope, UTC deadline, decision and verification code returned by IRMind. Use
plain text widgets. For the native surfaces and the GUI, render each
string using JSON quotation and escaping. Also escape DEL, C1 controls,
U+061C, U+200B–U+200F, U+2028–U+202E, U+2060–U+206F and U+FEFF
as lowercase Unicode escapes. Keep the literal escapes visible and
disable automatic links and markup. The approval view contains no
original records, excerpts, attachments or tool results. A literal argument
is displayed as an argument, even when it came from evidence. If a field
would need redaction, lossy normalization or truncation to pass ContentGuard
or fit the protocol, leave the request for the TUI. Never approve a
different value from the one displayed.

The first revision handles a single pending case tool request admitted by
the existing `/approvals` queue. A live child request must retain its
authenticated task binding and use the existing child decision path.
Everything that needs a separate confirmation flow, such as a budget
increase, policy or keystore change, package installation or plan
admission, stays in its current interface. There is no general signing
or keystore endpoint.

## Proposed protocol

Use `IRMIND-RPC-V2` plus NUL and `hello` with `version: 2` for this
extension. Keep the existing J encoding, framing, request/reply envelope,
limits and five case methods. The V1 transport continues to route decisions
through the TUI. V2 has four further methods. All fields in the table are
required, including fields whose values may be null. UUIDs are canonical,
and digests are 64 lowercase hex characters. States and methods are closed.

| Method | Params | Result |
| --- | --- | --- |
| `approval_prepare` | `{case_id,request_id,decision}`. A null `request_id` picks the oldest pending request by signed sequence. An explicit ID is the pending request digest. `decision` is `approve` or `deny`. | `{presentation,view,view_sha256,code,methods}`. `presentation` is a fresh UUID. `methods` lists currently available methods for this view. If the request cannot be shown exactly, return error 8. |
| `approval_submit` | `{case_id,presentation,view_sha256,method,passphrase_hex}`. Method is `touch_id`, `windows_hello`, or `keystore_passphrase`. Only the last accepts a lowercase hex encoding of exact UTF-8 bytes, at most 4,096 decoded bytes. The value must be null for native methods. | `{state:"authenticating"}` after accepting the one-time attempt. IRMind opens the OS dialog itself or verifies the supplied phrase inside its keystore backend. This reply carries no decision or execution permit. |
| `approval_status` | `{case_id,presentation}` | `{state}`, one of `ready`, `authenticating`, `approved`, `denied`, `reauth_failed`, `expired`, `stale`, or `cancelled`. A committed decision may also arrive as the existing guarded case event. Approval status says whether a decision was committed. Tool execution and its result follow the existing engine events. |
| `approval_cancel` | `{case_id,presentation}` | `{cancelled:bool}`. Cancels the presentation or in-flight authentication. A deliberate, signed denial uses `approval_submit` after preparing `decision:"deny"`. |

The exact `view` is
`{action,args,case_id,decision,effective_scope,expires_at,request_id}`.
`action` is the tool's canonical name, `args` maps names to exact strings,
and `effective_scope` is an exact string in the existing canonical
case-scope syntax. The engine computes it after intersecting applicable
case, organization, source and task restrictions. If a policy restriction
or execution destination is material and cannot be shown in that scope
and the named arguments, route the request to the TUI. `expires_at` is a UTC epoch second. The GUI applies
the specified reversible display escaping to every string and treats it
as text. A signed denial uses a fixed analyst-interface reason in the
existing receipt. Free-form denial reasons and edits stay in the TUI.

Errors 1–7 keep their V1 meanings. Error 8 has the fixed message
`Review this request in IRMind /approvals`. A different prepare while
a presentation is live returns busy. Once the presentation is replaced,
the old handle always returns expired.

The presentation digest is
`SHA-256("irmind-gui-approval-view-v1" || 00 || J(view))`.
The code is the first 16 lowercase hex characters of
`SHA-256("irmind-gui-approval-code-v1" || 00 || J({nonce,presentation,session,view_sha256}))`,
where `nonce` is 32 random bytes encoded as 64 lowercase hex characters
and stays in IRMind. The reply carries the ungrouped code. Both surfaces
display it as four groups of four characters separated by hyphens. The
GUI echoes the full view digest. The short code is for the analyst to
compare on the two surfaces. Neither value confers signing authority.

### Lifetime and commit

1. Under the case lock, authenticate the pending request and capture its
   immutable challenge, Analyst key fingerprint, effective policy and scope,
   relevant task/lease, selected decision and canonical view. The authoritative
   expiry is the earlier of the signed request deadline and 60 seconds from
   preparation, checked against both engine wall time and a monotonic clock.
   There is one live presentation per session. A repeated prepare for the
   same view returns it without extending the deadline.
2. A matching submit consumes the presentation's single authentication
   attempt. Release the case lock before showing UI or running a password
   check. Bound authentication by the same deadline and allow only one
   attempt in flight. Limit failed attempts to three per minute per local
   server session with a fixed error. A different method needs a fresh
   analyst-initiated presentation, subject to the original request deadline.
3. After success, IRMind reacquires the case lock and checks that the
   presentation is still active and unexpired. It reauthenticates the case
   chain and compares the exact pending challenge, canonical view, current
   Analyst identity, policy, scope and child lease when applicable. A changed
   request or policy, competing TUI decision, seal, expired lease, timeout
   or cancellation invalidates the attempt. Perform the recheck, one-time
   consumption and existing signed decision append under the same lock.
   Never release a tool permit before the durable append. A late callback
   or retry can neither sign again nor repeat execution. Use the existing
   policy and dispatch checks on the resulting call.
4. Close, cancellation and restart invalidate all pending presentations.
   A decision already committed survives disconnect and can be seen in the
   authenticated case. The audit keeps the existing Analyst-signed approval
   or denial receipt. It carries no passphrase, OS authentication material,
   or transport token. Offline verification proves the recorded decision
   and its bound request, and does not attest which device was used.
   This proposal adds an IPC version and no case or export record.

## Reauthentication on each platform

| Platform | IRMind action and prerequisites |
| --- | --- |
| macOS | IRMind creates a fresh `LAContext`, verifies `biometryType == touchID`, uses the biometric-only policy, sets Touch ID reuse duration to zero, and disables the system fallback button. The localized reason in the system dialog is generated from the request by IRMind and includes its decision, action, case, arguments, effective scope, expiry and code. Apple places this reason in the macOS dialog title and recommends short text. Enable Touch ID only for views and native configurations where the full escaped reason fits without elision and is readable. Require Intel and Apple Silicon verification of the standalone distribution binary, including the supported display settings and locales. For a view outside that verified limit or a machine without enrolled Touch ID, offer the explicit file-keystore option when available, or the TUI. Invalidate the context on cancellation and make late callbacks inert. |
| Windows | IRMind creates its own foreground request window and shows the exact escaped view there. On its UI thread, pass only that IRMind-owned HWND to `IUserConsentVerifierInterop::RequestVerificationForWindowAsync` with the IRMind-generated action and verification code. Require `Verified` for that invocation. Windows Hello can use its enrolled methods, including PIN. The desktop API requires Windows build 22000 or later. Enable it only when IRMind can own and show the window and the prompt binds to it in the active desktop session. Refuse an HWND from the external GUI. |
| Linux and fallback on macOS/Windows | The analyst explicitly selects the phrase route and enters the active encrypted file-keystore passphrase in a masked native input. Send it only over the admitted stdin pipe. IRMind verifies it anew using the active file vault's existing bounded Argon2id and authenticated decryption, holding its existing vault lock. Check that the vault still owns the same Analyst key. No new unlock, secret or verifier is issued. The OS keystore backend has no IRMind file-vault passphrase. On that backend, the method is unavailable, so the choices are native reauthentication where supported or the TUI. |

Apple API and prompt rendering documentation.
[`LAContext`](https://developer.apple.com/documentation/localauthentication/lacontext)
· [Biometric-only policy](https://developer.apple.com/documentation/LocalAuthentication/LAPolicy/deviceOwnerAuthenticationWithBiometrics)
· [Localization and title](https://developer.apple.com/documentation/localauthentication/lacontext/localizedreason)

Microsoft desktop interop and supported results.
[Desktop method and minimum version](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync)
· [UserConsentVerifier](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier)

Process the secret-bearing frame in a dedicated bounded decoder before
generic JSON logging or `Value` construction. Parse the fixed canonical J
shape into borrowed fields and decode the secret directly into zeroizing
memory. Avoid ordinary owned JSON strings, clones and debug displays for
that frame. Clear raw and decoded buffers on success, error, timeout,
cancellation and malformed input. Both sides keep the phrase out of
history, autofill, clipboard, command arguments, environment, configuration,
analytics, audit, model context, logs, transcripts and crash reports.
The trusted client suppresses IME or text-service capture where supported.
Do not advertise the phrase route if the client's input stack cannot meet
the handling requirements. Checked-in fixtures use synthetic phrases only.

## Threat model

| Attacker and input | Required control | Remaining boundary |
| --- | --- | --- |
| Compromised GUI that rewrites the view, sends a choice or sends a fake OS result | IRMind generates arguments, digest and native display from the authenticated case. It accepts success only from the OS callback for its own live instance. Check the action and matching code on the native surface. The GUI sends no authorization result. | A compromised GUI can record a phrase typed into it and lie about what the analyst reviewed. Stdio, code matching and zeroization cannot prevent capture at that endpoint. The phrase route requires a trusted GUI. A trusted OS prompt protects the native path from the GUI alone, subject to the verified display and session constraints. |
| Another local process attempting to read or write the transport | Inherit only the two private pipe ends into the authorized process, bind per session and case and require one timely reauthentication. No listening address, out-of-band signer, or trust in client-provided PID, token or HWND. | Protection assumes OS process/handle isolation. An attacker already able to inject into IRMind, read its memory or control the desktop or OS authentication is outside this boundary. Same-user process isolation must be tested, with no claims beyond what each OS enforces. |
| Hostile evidence embedded in a literal argument | Validate against the exact signed request and typed policy. Compare full canonical values. Reversibly escape and render inert strings. Keep evidence views and HTML outside the approval UI. | A plausible looking text value can still mislead a human. Keep argument labels, source and effective scope explicit when reviewing. |
| Replay, substitution, race or restart | Bind the request, view, GUI session, case, decision, expiry and OS result. Check current state and existing signed decisions under the case lock. Consume the attempt once. Reject a stale callback, changed effective scope, or duplicate commit. | A committed decision remains in the case if the client loses the response. Refresh authenticated state. Do not retry the approval or execution automatically. |

Current implementation boundaries audited for this design.
[Stdio startup admission](https://github.com/ns2switch/irmind/blob/0756bc29/crates/bin/src/startup.rs)
· [Approval resolution](https://github.com/ns2switch/irmind/blob/0756bc29/crates/app/src/approvals/resolution.rs)
· [File vault](https://github.com/ns2switch/irmind/blob/0756bc29/crates/modules/keystore-file/src/file_backend.rs)
· [OS keystore](https://github.com/ns2switch/irmind/blob/0756bc29/crates/modules/keystore-os/src/lib.rs)

## Native dependency review

These candidates were resolved in a standalone Cargo manifest against
crates.io on 2026-11-27 using Rust 1.97.1. The closure includes normal and
build edges, including proc macros. Byte totals sum registry archives and
their unpacked file sizes. They are source/cache measurements, not the
increase in the linked IRMind executable. The production manifests and
lockfiles are outside this dependency probe.

| Candidate | Target closure, relative to `0756bc29` | Archive / unpacked size | License and platform dependency |
| --- | --- | --- | --- |
| Touch ID using Rust bindings | 6 packages, 5 new, identical on both macOS targets. `objc2-local-authentication 0.3.2`, `objc2-foundation 0.3.2`, `block2 0.6.2`, `objc2 0.6.5`, `objc2-encode 4.1.0`. Reuses `bitflags 2.13.2`. | 749,105 / 4,737,975 bytes total. 697,427 / 4,491,919 new. | MIT for the four support crates. LocalAuthentication bindings offer Zlib, Apache-2.0 or MIT. `bitflags` is MIT or Apache-2.0. Runtime uses Apple's LocalAuthentication and Foundation frameworks. |
| Windows Hello using Rust bindings | 15 packages, 10 new on x86-64 Windows. `windows 0.62.2`, `windows-core 0.62.2`, `windows-collections 0.3.2`, `windows-future 0.3.2`, `windows-numerics 0.3.1`, `windows-implement 0.60.2`, `windows-interface 0.59.3`, `windows-result 0.4.1`, `windows-strings 0.5.1`, `windows-threading 0.2.1`. Reuses `windows-link 0.2.1`, `proc-macro2 1.0.107`, `quote 1.0.47`, `syn 2.0.119`, `unicode-ident 1.0.27`. The existing `windows-sys` is separate from these typed WinRT interfaces. | 9,956,454 / 117,940,866 bytes total. 9,502,897 / 114,869,304 new. The `windows` archive accounts for most of the unpacked size. | Microsoft packages MIT or Apache-2.0. Existing `unicode-ident` also requires Unicode-3.0. System COM, WinRT and windowing libraries provide the runtime. |
| System SDK bridge on either platform | Zero additional registry packages if compiled with the existing pinned release SDK and linker. A narrow Objective-C or C++ bridge would introduce a first-party native build unit and FFI boundary. | Zero registry archive bytes. Native object and linked sizes still require measurement. | First-party glue uses the project license and system SDK terms. No framework files or SDK headers would ship with IRMind. Windows uses Windows SDK desktop WinRT headers. Avoid hand-written Rust COM vtables. |

All candidate crate licenses appear in the current `deny.toml` allowlist.
The production lock and release SBOM must still pass normal CI before
integration. For the probe, disable default features. macOS used only
`LAContext,LABase,LABiometryType,block2` on
`objc2-local-authentication`, `NSString,NSError` on
`objc2-foundation`, and `alloc` on `block2`. Windows used
`std,Security_Credentials_UI,Win32_System_WinRT,Win32_System_LibraryLoader,Win32_UI_WindowsAndMessaging`.
Repeat via `cargo tree --target <triple> -e normal,build --locked` with
the listed roots and versions. The Windows projection contains the
required desktop interop method.

Primary package and SDK sources.
[objc2 LocalAuthentication Cargo manifest](https://docs.rs/crate/objc2-local-authentication/0.3.2/source/Cargo.toml)
· [Windows Rust Cargo manifest](https://docs.rs/crate/windows/0.62.2/source/Cargo.toml)
· [Microsoft Windows SDK C++/WinRT headers](https://learn.microsoft.com/en-us/windows/apps/develop/cpp-winrt/get-started)

Recommend the typed, target-only Rust bindings for review. They keep the
platform FFI and callback lifetime within a small adapter and avoid
adding a different native compilation path. Linked size is **unmeasured**
at this design stage. The implementation PR must measure stripped binary
size and section deltas with each backend off/on in the same release job,
with the pinned SDK and toolchain, on Intel and Apple Silicon macOS and
x86-64 Windows. Check that the Linux distribution targets gain no new
production dependency, confirm linkage/import tables and reproducibility,
and include the required third-party notices. Apply the existing
first-party unsafe boundary to the adapter. Do not switch to an SDK
bridge or widen the set of dependencies without review.

## Acceptance before enabling

- Native sessions show the exact fields and code with leading, trailing,
  Unicode and maximum-size values. Test that a truncated Touch ID prompt,
  unavailable hardware, Windows foreground failure, non-verified OS result,
  wrong keystore backend or wrong phrase causes no signature.
- With synthetic cases, run approve and deny, verify the existing signed
  decision, and check that any result was dispatched only after commit.
  The test covers a live child request and concurrent resolution from the
  TUI. Verify expiry and cancellation during the native callback and while
  the case lock is contended.
- A fake GUI sends altered arguments, a fake OS success, another session's
  handle and a replay before and after restart. Cases include a policy,
  scope, Analyst key or lease change before commit. No second append or
  dispatch occurs.
- Feed malformed secret frames, hostile escaped arguments and binary
  controls through the GUI harness. Check the case, export, stderr,
  diagnostics and any captured crash reports for synthetic secret markers. Verify that neither app converts evidence to active markup.
- Exercise native dialogs on Windows 11 and the two macOS architectures
  with an interactive desktop and enrolled credentials. CI mocks cover
  the state machine. Native availability stays off on unverified systems
  or display configurations.
