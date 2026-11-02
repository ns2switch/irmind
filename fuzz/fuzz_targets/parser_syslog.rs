#![no_main]
use irmind_app::{CancellationToken, LogParser as _, StreamingEventParser as _, sha256};
use irmind_mod_parser_syslog::{LegacyTimestamp, SyslogParser};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let context = LegacyTimestamp::new(2026, 60).ok();
        for parser in [SyslogParser::default(), SyslogParser::new(context)] {
            let _ = parser.detect("fuzz.log", bytes);
            let _ = parser.parse_reader_report(
                "fuzz.log",
                &mut std::io::Cursor::new(bytes),
                sha256(bytes),
                &CancellationToken::new(),
                &mut |_| Ok(()),
            );
        }
    }
});
