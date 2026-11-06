#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 4 * 1024 * 1024 { irmind_mod_parser_evtx::fuzz_protocol(bytes); }
});
