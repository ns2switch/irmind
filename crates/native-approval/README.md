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

Use Windows 11 build 22000 or later with Hello already enrolled, an
interactive desktop and the Rust toolchain pinned by the candidate. Use
an isolated checkout and synthetic cases only.

1. Open [PR #450](https://github.com/ns2switch/irmind/pull/450), copy the
   full candidate commit from its **Commits** tab and confirm the matrix is
   green for that commit. Fetch `refs/pull/450/head` from the official GitHub
   repository, check out that commit detached and compare `git rev-parse HEAD`
   to the copied hash. Check that `git status --porcelain` is empty.
2. Build the local trial executables from the verified checkout with the
   pinned dependency checksums. `cargo test --no-run` prints the executable
   paths. Record each SHA-256 using `Get-FileHash -Algorithm SHA256 <path>`.
   Use only these locally built files. These trial executables are separate
   from the published IRMind packages.

   ```powershell
   cargo test --release --locked -p irmind-native-approval --no-run
   cargo test --release --locked -p irmind-infra --lib --no-run
   ```

3. Run the `irmind_infra` trial executable. It creates temporary keys and
   synthetic cases with a simulated provider. Complete both dialogs, first
   for approving and then for denying a request. The test verifies the
   Analyst signature and one dispatch after the approval commit, and a
   signed denial with zero dispatches in the other case.

   ```powershell
   & <infra-executable> engine_rpc_native_windows_hello_signed_decision --ignored --test-threads 1
   ```

4. In both dialogs, scroll through IRMind's own review window. Check that the
   complete action, case UUID, arguments, effective scope, decision, expiry
   and verification code are readable. Compare the action and complete code
   with the Windows Hello prompt. A Continue click only opens Hello.
5. Run `windows_hello_native_decline` on the `irmind_native_approval`
   trial executable with `--ignored --test-threads 1`. Confirm the real
   prompt appears, then cancel it. Repeat the test and try closing the
   review window and letting the request expire while Hello is open. Record
   the actual prompts and results. When practical, also try unsuccessful
   verification attempts and check that none returns success.
6. Run `engine_rpc_v2_discards_a_late_authentication_after_cancellation`
   and `engine_rpc_v2_rechecks_the_deadline_and_competing_decisions_under_lock`
   on the `irmind_infra` executable with `--test-threads 1`. These synthetic
   cases deliver a late success and prove it cannot sign or dispatch.
   Also exercise a late confirmation in the real dialog if the OS permits
   it after expiry and report whether the dialog was already dismissed.

Report the commit, executable hashes, OS build, display resolution,
accessibility scale, locale and the result of each step. Include any
clipped text or unexpected completion. Keep PINs, biometric material and
personal information out of reports and screenshots.
