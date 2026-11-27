#![cfg(windows)]
//! Calls are confined to the thread that owns the request window.
#![allow(unsafe_code)]

use std::{
    ptr::null_mut,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use windows::{
    Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier},
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            WinRT::{
                IUserConsentVerifierInterop, RO_INIT_SINGLETHREADED, RoInitialize, RoUninitialize,
            },
        },
        UI::WindowsAndMessaging::{
            CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow,
            DispatchMessageW, ES_MULTILINE, ES_READONLY, GetForegroundWindow, GetWindowTextLengthW,
            GetWindowTextW, HMENU, IsWindow, MSG, PM_REMOVE, PeekMessageW, PostMessageW,
            RegisterClassW, SW_SHOW, ShowWindow, TranslateMessage, UnregisterClassW,
            WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CLOSE, WM_COMMAND, WM_DESTROY, WNDCLASSW,
            WS_BORDER, WS_CAPTION, WS_CHILD, WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
            WS_VSCROLL,
        },
    },
    core::{HSTRING, PCWSTR, Result, factory, w},
};

const CLASS: PCWSTR = w!("IRMindApprovalReviewV1");
const CONTINUE: usize = 1;
const REVIEWED: u32 = WM_APP + 1;
const FULL_TEXT_LIMIT: usize = 65_536;
const MESSAGE_LIMIT: usize = 256;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Verify one approval with a native window containing the exact escaped view.
/// An unavailable, expired, or cancelled verification always returns false.
pub fn verify(
    exact_view: &str,
    system_message: &str,
    deadline: Instant,
    cancelled: impl Fn() -> bool,
) -> bool {
    if exact_view.is_empty()
        || exact_view.encode_utf16().count() > FULL_TEXT_LIMIT
        || exact_view.contains('\0')
        || system_message.is_empty()
        || system_message.encode_utf16().count() > MESSAGE_LIMIT
        || system_message.contains('\0')
        || stopped(deadline, &cancelled)
    {
        return false;
    }
    verify_once(exact_view, system_message, deadline, &cancelled).unwrap_or(false)
}

fn verify_once(
    exact_view: &str,
    system_message: &str,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<bool> {
    let _apartment = Apartment::enter()?;
    let window = ReviewWindow::new(exact_view)?;
    while !stopped(deadline, cancelled) && window.exists() {
        if window.pump() && window.foreground() {
            let service: IUserConsentVerifierInterop = factory::<UserConsentVerifier, _>()?;
            let message = HSTRING::from(system_message);
            let operation =
                desktop_operation(UserConsentVerifier::RequestVerificationAsync, || {
                    // SAFETY: The live HWND belongs to the WinRT STA making the request.
                    // The HSTRING and typed result IID stay valid through this call.
                    unsafe { service.RequestVerificationForWindowAsync(window.handle, &message) }
                })?;
            let (send, receive) = mpsc::sync_channel(1);
            operation.when(move |result| {
                let _ = send.try_send(
                    result.is_ok_and(|result| result == UserConsentVerificationResult::Verified),
                );
            })?;
            while !stopped(deadline, cancelled) && window.exists() {
                window.pump();
                match receive.try_recv() {
                    Ok(verified) => {
                        return Ok(verified && !stopped(deadline, cancelled) && window.exists());
                    }
                    Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => thread::sleep(POLL_INTERVAL),
                }
            }
            operation.Cancel()?;
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    Ok(false)
}

// Infer the projected WinRT result type from the declared API signature.
// The non-desktop entry point is never invoked.
fn desktop_operation<T>(
    _: fn(&HSTRING) -> Result<T>,
    desktop: impl FnOnce() -> Result<T>,
) -> Result<T> {
    desktop()
}

fn stopped(deadline: Instant, cancelled: &impl Fn() -> bool) -> bool {
    Instant::now() >= deadline || cancelled()
}

struct Apartment;

impl Apartment {
    fn enter() -> Result<Self> {
        // SAFETY: Balance a successful call on this thread in Drop.
        unsafe { RoInitialize(RO_INIT_SINGLETHREADED)? };
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: The guard never leaves its originating verification thread.
        unsafe { RoUninitialize() };
    }
}

struct ReviewWindow {
    handle: HWND,
    module: windows::Win32::Foundation::HINSTANCE,
}

impl ReviewWindow {
    fn new(exact_view: &str) -> Result<Self> {
        // SAFETY: None selects the module for the executable in this process.
        let module = unsafe { GetModuleHandleW(None)? }.into();
        let class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(review_proc),
            hInstance: module,
            lpszClassName: CLASS,
            ..Default::default()
        };
        // SAFETY: The class holds static code and a static NUL-terminated name.
        if unsafe { RegisterClassW(&raw const class) } == 0 {
            return Err(windows::core::Error::from_thread());
        }
        let mut window = Self {
            handle: HWND(null_mut()),
            module,
        };
        // SAFETY: CLASS is registered by this process on this thread. No client
        // handle, userdata or pointer is passed to the window procedure.
        window.handle = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                CLASS,
                w!("IRMind approval review"),
                WS_POPUP | WS_CAPTION | WS_SYSMENU,
                100,
                100,
                730,
                520,
                None,
                None,
                Some(module),
                None,
            )?
        };
        window.create_controls(exact_view)?;
        // SAFETY: This is our live, thread-owned top-level window.
        let _ = unsafe { ShowWindow(window.handle, SW_SHOW) };
        Ok(window)
    }

    fn create_controls(&self, exact_view: &str) -> Result<()> {
        let text: Vec<_> = exact_view.encode_utf16().chain([0]).collect();
        // SAFETY: EDIT is a built-in control. The UTF-16 buffer has a
        // terminating NUL and stays alive until window creation returns.
        let field = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("EDIT"),
                PCWSTR(text.as_ptr()),
                WS_CHILD
                    | WS_VISIBLE
                    | WS_BORDER
                    | WS_TABSTOP
                    | WS_VSCROLL
                    | WINDOW_STYLE(u32::try_from(ES_MULTILINE | ES_READONLY).unwrap_or_default()),
                12,
                12,
                686,
                412,
                Some(self.handle),
                None,
                Some(self.module),
                None,
            )?
        };
        // SAFETY: field is the child control just created on this thread.
        let units = unsafe { GetWindowTextLengthW(field) };
        if usize::try_from(units).ok() != Some(text.len() - 1) {
            return Err(windows::core::Error::from_thread());
        }
        let mut displayed = vec![0u16; text.len()];
        // SAFETY: The writable UTF-16 buffer includes room for the terminal NUL.
        let copied = unsafe { GetWindowTextW(field, &mut displayed) };
        if copied != units || displayed != text {
            return Err(windows::core::Error::from_thread());
        }
        // SAFETY: BUTTON is built in. The HMENU parameter is the child control
        // identifier documented for this call and never treated as a handle.
        unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("BUTTON"),
                w!("Continue to Windows Hello"),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                12,
                434,
                250,
                30,
                Some(self.handle),
                Some(HMENU(CONTINUE as *mut _)),
                Some(self.module),
                None,
            )?
        };
        Ok(())
    }

    fn exists(&self) -> bool {
        // SAFETY: Non-mutating validity test of the window handle we own.
        unsafe { IsWindow(Some(self.handle)).as_bool() }
    }

    fn foreground(&self) -> bool {
        // SAFETY: This getter reads the current desktop foreground handle.
        unsafe { GetForegroundWindow() == self.handle }
    }

    fn pump(&self) -> bool {
        let mut msg = MSG::default();
        let mut reviewed = false;
        for _ in 0..32 {
            // SAFETY: msg is writable and the HWND is restricted to our presentation.
            if !unsafe { PeekMessageW(&raw mut msg, Some(self.handle), 0, 0, PM_REMOVE) }.as_bool()
            {
                break;
            }
            if msg.hwnd == self.handle && msg.message == REVIEWED {
                reviewed = true;
            } else {
                // SAFETY: msg was filled by PeekMessageW for this window.
                unsafe {
                    let _ = TranslateMessage(&raw const msg);
                    DispatchMessageW(&raw const msg);
                }
            }
        }
        reviewed
    }
}

impl Drop for ReviewWindow {
    fn drop(&mut self) {
        if self.exists() {
            // SAFETY: Destruction occurs on the thread that created this window.
            let _ = unsafe { DestroyWindow(self.handle) };
        }
        // SAFETY: The class was registered by this owner and the window is gone.
        let _ = unsafe { UnregisterClassW(CLASS, Some(self.module)) };
    }
}

unsafe extern "system" fn review_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_COMMAND if wparam.0 == CONTINUE => {
            // SAFETY: The message contains no pointers. The event starts
            // authentication and carries no authority on its own.
            let _ = unsafe { PostMessageW(Some(hwnd), REVIEWED, WPARAM(0), LPARAM(0)) };
            LRESULT(0)
        }
        WM_CLOSE => {
            // SAFETY: The window procedure runs on the owning UI thread.
            let _ = unsafe { DestroyWindow(hwnd) };
            LRESULT(0)
        }
        WM_DESTROY => LRESULT(0),
        // SAFETY: Unhandled messages are passed to the documented default
        // procedure with their original system-provided parameters.
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIEW: &str = "Action: ti_lookup_external\r\nCase: 10000000-0000-4000-8000-000000000001\r\nArguments: ioc=\"example.test\"\r\nEffective scope: local\r\nDecision: approve\r\nExpiry: within 60 seconds\r\nCode: 5d02-781d-508e-2fd7";
    const MESSAGE: &str = "IRMind synthetic approval: ti_lookup_external 5d02-781d-508e-2fd7";

    #[test]
    fn expired_or_invalid_requests_do_not_open_a_window() {
        assert!(!verify(VIEW, MESSAGE, Instant::now(), || false));
        assert!(!verify(
            "bad\0view",
            MESSAGE,
            Instant::now() + Duration::from_secs(1),
            || false
        ));
        assert!(!verify(
            VIEW,
            MESSAGE,
            Instant::now() + Duration::from_secs(1),
            || true
        ));
    }

    #[test]
    #[ignore = "needs an interactive Windows 11 desktop with an enrolled Windows Hello method"]
    fn windows_hello_native_approve() {
        let expires = Instant::now() + Duration::from_mins(1);
        assert!(verify(VIEW, MESSAGE, expires, || false));
    }

    #[test]
    #[ignore = "needs an interactive Windows 11 desktop; cancel the Windows Hello dialog"]
    fn windows_hello_native_decline() {
        let expires = Instant::now() + Duration::from_mins(1);
        assert!(!verify(VIEW, MESSAGE, expires, || false));
    }
}
