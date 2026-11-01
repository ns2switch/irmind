#![no_main]
use irmind_app::{CancellationToken, LogParser as _, StreamingEventParser as _, sha256};
use irmind_mod_parser_suricata::SuricataParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let _ = SuricataParser.detect("fuzz.jsonl", bytes);
        let _ = SuricataParser.parse_reader_report(
            "fuzz.jsonl",
            &mut bytes.as_ref(),
            sha256(bytes),
            &CancellationToken::new(),
            &mut |_| Ok(()),
        );
    }
});
