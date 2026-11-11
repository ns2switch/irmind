#![no_main]
use irmind_app::{
    CancellationToken, LogParser as _, ParserTimeBasis, ParserTimeContext, SourceDecoder as _,
    sha256,
};
use irmind_mod_parser_syslog::SyslogParser;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let Some(temporal) = ParserTimeContext::new(2026, 60, true, ParserTimeBasis::Analyst).ok()
        else {
            return;
        };
        let Ok(configured) = SyslogParser::default().with_time_context(&temporal) else {
            return;
        };
        let source =
            irmind_app::source_mapping::SourceReferenceV1::file("fuzz.log").expect("fixed source");
        let cancel = CancellationToken::new();
        for time_context in [None, Some(&temporal)] {
            let _ = irmind_mod_parser_syslog::SyslogSourceDecoder.decode_reader(
                irmind_app::source_mapping::SourceInput {
                    metadata: irmind_app::source_mapping::SourceMetadata {
                        source: &source,
                        evidence_hash: sha256(bytes),
                        time_context,
                        cancel: &cancel,
                    },
                    reader: &mut std::io::Cursor::new(bytes),
                },
                &mut |_| Ok(()),
            );
        }
        let default = SyslogParser::default();
        for parser in [&default as &dyn irmind_app::LogParser, configured.as_ref()] {
            let _ = parser.detect("fuzz.log", bytes);
            let _ = parser.time_context_requirement("fuzz.log", bytes);
        }
    }
});
