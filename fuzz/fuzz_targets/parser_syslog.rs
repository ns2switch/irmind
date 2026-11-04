#![no_main]
use irmind_app::{CancellationToken, LogParser as _, ParserTimeBasis, ParserTimeContext, sha256};
use irmind_mod_parser_syslog::{LegacyTimestamp, SyslogParser};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let context = LegacyTimestamp::new(2026, 60).ok();
        let Some(temporal) = ParserTimeContext::new(2026, 60, true, ParserTimeBasis::Analyst).ok()
        else {
            return;
        };
        let Ok(configured) = SyslogParser::default().with_time_context(&temporal) else {
            return;
        };
        let historical = SyslogParser::new(context);
        let default = SyslogParser::default();
        for parser in [
            &default as &dyn irmind_app::LogParser,
            &historical,
            configured.as_ref(),
        ] {
            let _ = parser.detect("fuzz.log", bytes);
            let _ = parser.time_context_requirement("fuzz.log", bytes);
            let _ = parser.parse_indexed_reader_report(
                "fuzz.log",
                &mut std::io::Cursor::new(bytes),
                sha256(bytes),
                &CancellationToken::new(),
                &mut |_| Ok(()),
            );
        }
    }
});
