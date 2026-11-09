#![no_main]
use irmind_app::{
    CancellationToken, EventParser as _, LogParser as _, SourceDecoder as _,
    StreamingEventParser as _, sha256,
};
use irmind_mod_parser_json::JsonParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let cancel = CancellationToken::new();
        let source = irmind_domain::SourceReferenceV1::file("fuzz.json").unwrap();
        let _ = irmind_mod_parser_json::JsonSourceDecoder.decode_reader(
            irmind_app::source_mapping::SourceInput {
                metadata: irmind_app::source_mapping::SourceMetadata {
                    source: &source,
                    evidence_hash: sha256(bytes),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |_| Ok(()),
        );
        let _ = JsonParser.detect("fuzz.jsonl", bytes);
        let _ = JsonParser.parse("fuzz.json", bytes);
        let _ = JsonParser.parse_reader_report(
            "fuzz.json",
            &mut std::io::Cursor::new(bytes),
            sha256(bytes),
            &CancellationToken::new(),
            &mut |_| Ok(()),
        );
        let _ = JsonParser.parse_indexed_reader_report(
            "fuzz.jsonl",
            &mut std::io::Cursor::new(bytes),
            sha256(bytes),
            &CancellationToken::new(),
            &mut |_| Ok(()),
        );
    }
});
