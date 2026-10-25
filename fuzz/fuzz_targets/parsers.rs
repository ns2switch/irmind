#![no_main]
use irmind_app::EventParser as _;
use irmind_mod_parser_json::JsonParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let _ = JsonParser.parse("fuzz.json", bytes);
    }
});
