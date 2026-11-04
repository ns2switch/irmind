#![no_main]
use irmind_app::{CancellationToken, LogParser as _, StreamingEventParser as _, sha256};
use irmind_mod_parser_hayabusa::HayabusaParser;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let _ = HayabusaParser.detect("fuzz.log", bytes);
        let _ = HayabusaParser.parse_indexed_reader_report(
            "fuzz.log",
            &mut std::io::Cursor::new(bytes),
            sha256(bytes),
            &CancellationToken::new(),
            &mut |_| Ok(()),
        );
    }
});
