# IRMind native approval

The Windows Hello adapter is under validation. The protocol does not
advertise it. The adapter receives an escaped presentation from an
IRMind caller and returns one Boolean for that presentation. It owns no
Analyst key and has no access to the case or keystore.

## Windows trust boundary

Windows 11 build 22000 or later is required for the desktop interop API.
An IRMind-owned foreground window contains the complete review in a
read-only control. The Continue button starts an independent Windows Hello
check. The adapter supplies its own HWND. A result other than `Verified`,
an expired request, a cancelled request and a destroyed window all fail
closed. The app still rechecks policy, scope and lease before signing.

| Operation | Safety invariant |
| --- | --- |
| `RoInitialize`, `RoUninitialize` | A fresh thread enters an STA. Its guard balances only a successful initialization, after the UI and WinRT objects are dropped. |
| `GetModuleHandleW`, `RegisterClassW`, `UnregisterClassW` | Use IRMind's module, the fixed class name and a static callback. Unregister only the class this call successfully registered. |
| `CreateWindowExW` | The top-level window is created by IRMind. Child controls use built-in classes and borrow NUL-terminated process-owned buffers for the call. Their identifiers carry no authority. |
| `GetWindowTextLengthW`, `GetWindowTextW` | A result whose text or length differs from the exact review is rejected before calling Hello. |
| `ShowWindow`, `IsWindow`, `GetForegroundWindow`, `DestroyWindow` | Operate on the local desktop. The top-level window stays on its creating thread. A foreground handle other than the one just created is insufficient. |
| `PeekMessageW`, `TranslateMessage`, `DispatchMessageW` | Dequeue a bounded batch into initialized storage for the owned window. The standard dispatcher invokes the process-local procedure. |
| `PostMessageW`, `DefWindowProcW` | The callback posts a pointer-free signal to its own window and forwards other parameters unchanged to the default procedure. The signal initiates authentication only. |
| `RequestVerificationForWindowAsync` | Pass the active IRMind HWND, the process-generated verification text and the WinRT projection's actual result IID. The completion closure captures only a bounded result channel. |

Cancellation and expiry are checked in the UI pump and again after a
result. Dropping the receiver makes late callbacks inert. Neither the
user's PIN nor any biometric material crosses the adapter.

## Manual Windows witness

Use a real Windows 11 desktop and an enrolled Hello method. Run each
test on its own, with the release toolchain and a synthetic case.

```powershell
cargo test --release -p irmind-native-approval windows_hello_native_approve -- --ignored --test-threads 1
cargo test --release -p irmind-native-approval windows_hello_native_decline -- --ignored --test-threads 1
```

For the first test, read the entire IRMind window, scroll to the final
code if needed, choose Continue, compare the action and code in the OS
prompt and complete Hello. For the second, choose Continue, then cancel
the OS prompt before it expires. Record OS build, accessibility scale,
display resolution and locale. Also exercise closing the review window,
focus loss, non-enrollment and a late result. The automated witness
reports the outcome. The analyst must record the dialog actually shown.

Before enabling RPC, also run the full real-process approval, cancellation
and replay cases with this adapter bound to RPC. The standalone witness
covers only the desktop API and the window. Distribution verification
must include paired release builds, the licenses, SBOM and import tables
as well as artifact reproducibility.

For the signed-case witness, run the approved Windows adapter through
RPC V2 and choose Continue followed by successful Hello for the displayed
synthetic denial. The test then verifies the signed decision and zero
dispatches. This route is linked into the test harness only.

```powershell
cargo test --release -p irmind-infra --lib engine_rpc_native_windows_hello_signed_decision -- --ignored --test-threads 1
```
