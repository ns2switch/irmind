#![no_main]
use irmind_app::ContentGuard as _;
use irmind_security::MandatoryGuard;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    let guard = GUARD.get_or_init(|| MandatoryGuard::new().expect("guard self-test"));
    let input = String::from_utf8_lossy(bytes);
    let _ = guard.screen(&input);
});

static GUARD: OnceLock<MandatoryGuard> = OnceLock::new();
