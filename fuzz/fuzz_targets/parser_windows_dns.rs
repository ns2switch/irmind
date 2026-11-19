#![no_main]
use irmind_app::source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1};
use irmind_app::{CancellationToken, LogParser as _, SourceDecoder as _, sha256};
use irmind_mod_parser_windows_dns::{WindowsDnsParser, WindowsDnsSourceDecoder};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4_194_304 {
        return;
    }
    let source = SourceReferenceV1::file("dns.log").expect("fixed name");
    let cancel = CancellationToken::new();
    let _ = WindowsDnsParser.detect("dns.log", bytes);
    let _ = WindowsDnsSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: sha256(bytes),
                time_context: Some(&irmind_app::ParserTimeContext::new(2026, 0, false, irmind_app::ParserTimeBasis::Analyst).expect("fixed context")),
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut std::io::Cursor::new(bytes),
        },
        &mut |_| Ok(()),
    );
});
