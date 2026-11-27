#![cfg(target_os = "macos")]
#![allow(unsafe_code)]

use block2::RcBlock;
use objc2::{rc::autoreleasepool, runtime::Bool};
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};
use std::{
    sync::mpsc::{self, RecvTimeoutError},
    time::{Duration, Instant},
};

const POLL: Duration = Duration::from_millis(20);

/// Verify a single Touch ID prompt with the process-owned request text.
/// The caller supplies the measured title limit for its verified desktop.
pub fn verify_touch_id(
    reason: &str,
    measured_title_limit: u16,
    deadline: Instant,
    cancelled: impl Fn() -> bool,
) -> bool {
    if reason.is_empty()
        || !reason.is_ascii()
        || reason.chars().any(char::is_control)
        || reason.encode_utf16().count() > usize::from(measured_title_limit)
        || stopped(deadline, &cancelled)
    {
        return false;
    }
    autoreleasepool(|_| verify_once(reason, deadline, &cancelled))
}

fn verify_once(reason: &str, deadline: Instant, cancelled: &impl Fn() -> bool) -> bool {
    // SAFETY: Use a new context confined to the thread that owns the pool.
    let context = unsafe { LAContext::new() };
    let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
    // SAFETY: The context is live and this is a documented closed policy.
    if unsafe { context.canEvaluatePolicy_error(policy) }.is_err() {
        return false;
    }
    // SAFETY: Query the same context after a successful capability check.
    if unsafe { context.biometryType() } != LABiometryType::TouchID {
        return false;
    }
    let hide = NSString::from_str("");
    // SAFETY: The context and title are valid Objective-C objects. The
    // empty localized fallback label disables the system fallback button.
    unsafe { context.setLocalizedFallbackTitle(Some(&hide)) };
    // SAFETY: Zero is the documented value disabling reuse on this context.
    unsafe { context.setTouchIDAuthenticationAllowableReuseDuration(0.0) };
    let reason = NSString::from_str(reason);
    let (send, receive) = mpsc::sync_channel(1);
    let reply = RcBlock::new(move |ok: Bool, _: *mut NSError| {
        let _ = send.try_send(ok.as_bool());
    });
    if stopped(deadline, cancelled) {
        return false;
    }
    // SAFETY: LocalAuthentication copies the completion block. Its only
    // captured value is a Send channel; it never dereferences the error
    // pointer or accesses the context, case, engine, or any keystore.
    unsafe { context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply) };
    let mut verified = false;
    while !stopped(deadline, cancelled) {
        match receive.recv_timeout(POLL) {
            Ok(result) => {
                verified = result && !stopped(deadline, cancelled);
                break;
            }
            Err(RecvTimeoutError::Timeout) => (),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    // SAFETY: Invalidate the still-live context on its creating thread;
    // late callbacks can only write to the bounded, soon-dropped channel.
    unsafe { context.invalidate() };
    verified && !stopped(deadline, cancelled)
}

fn stopped(deadline: Instant, cancelled: &impl Fn() -> bool) -> bool {
    Instant::now() >= deadline || cancelled()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REASON: &str =
        "approve ti_lookup_external 10000000-0000-4000-8000-000000000001 1234-5678-9abc-def0";

    #[test]
    fn short_or_expired_surfaces_do_not_start_touch_id() {
        assert!(!verify_touch_id(
            REASON,
            64,
            Instant::now() + Duration::from_secs(1),
            || false,
        ));
        assert!(!verify_touch_id(REASON, 128, Instant::now(), || false));
        assert!(!verify_touch_id(
            REASON,
            128,
            Instant::now() + Duration::from_secs(1),
            || true,
        ));
    }

    #[test]
    #[ignore = "requires a real macOS desktop with enrolled Touch ID"]
    fn touch_id_native_verify_dialog() {
        let deadline = Instant::now() + Duration::from_mins(1);
        assert!(verify_touch_id(REASON, 128, deadline, || false));
    }

    #[test]
    #[ignore = "requires a real macOS desktop; cancel the Touch ID dialog"]
    fn touch_id_native_cancel_dialog() {
        let deadline = Instant::now() + Duration::from_mins(1);
        assert!(!verify_touch_id(REASON, 128, deadline, || false));
    }
}
