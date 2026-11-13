#![no_main]
use irmind_app::{
    CancellationToken, LogParser as _, ParserTimeBasis, ParserTimeContext, SourceDecoder as _,
    sha256,
};
use irmind_mod_parser_linux::LinuxParser;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    let parser = LinuxParser::default();
    let year = bytes.get(..2).map_or(2026, |value| {
        u16::from_le_bytes([value[0], value[1]]) % 9999 + 1
    });
    let Some(context) = ParserTimeContext::new(year, 60, true, ParserTimeBasis::Analyst).ok()
    else {
        return;
    };
    let Ok(configured) = parser.with_time_context(&context) else {
        return;
    };
    for selected in [&parser as &dyn irmind_app::LogParser, configured.as_ref()] {
        let _ = selected.detect("synthetic.log", bytes);
        let _ = selected.time_context_requirement("synthetic.log", bytes);
    }
    let source =
        irmind_app::source_mapping::SourceReferenceV1::file("synthetic.log").expect("fixed source");
    let cancel = CancellationToken::new();
    for time_context in [None, Some(&context)] {
        let _ = irmind_mod_parser_linux::LinuxSourceDecoder.decode_reader(
            irmind_app::source_mapping::SourceInput {
                metadata: irmind_app::source_mapping::SourceMetadata {
                    cluster_context: None,
                    source: &source,
                    evidence_hash: sha256(bytes),
                    time_context,
                    cancel: &cancel,
                },
                reader: &mut bytes.as_ref(),
            },
            &mut |_| Ok(()),
        );
    }
});
