#![no_main]
use irmind_app::{
    CancellationToken, EventParser as _, LogParser as _, StreamingEventParser as _, sha256,
};
use irmind_mod_parser_json::JsonParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let _ = JsonParser.detect("fuzz.jsonl", bytes);
        let _ = JsonParser.parse("fuzz.json", bytes);
        let _ = JsonParser.parse_reader_report(
            "fuzz.jsonl",
            &mut bytes.as_ref(),
            sha256(bytes),
            &CancellationToken::new(),
            &mut |_| Ok(()),
        );
    }
});
