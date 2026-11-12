#![no_main]
use irmind_infra::verify_export;
use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 2 * 1024 * 1024 {
        return;
    }
    if let Ok(mut file) = tempfile::NamedTempFile::new() {
        if file.write_all(bytes).is_ok() {
            let _ = verify_export(file.path());
        }
    }
});
