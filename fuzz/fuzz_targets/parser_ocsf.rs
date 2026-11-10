#![no_main]

use irmind_app::{
    CancellationToken, LogParser as _, SourceDecoder as _, StreamingEventParser as _, sha256,
};
use irmind_mod_parser_ocsf::OcsfParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let cancel = CancellationToken::new();
        let reference = irmind_app::source_mapping::SourceReferenceV1::file("fuzz.ndjson")
            .expect("fixed source");
        let _ = irmind_mod_parser_ocsf::OcsfSourceDecoder.decode_reader(
            irmind_app::source_mapping::SourceInput {
                metadata: irmind_app::source_mapping::SourceMetadata {
                    source: &reference,
                    evidence_hash: sha256(bytes),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |_| Ok(()),
        );
        let _ = OcsfParser.detect("fuzz.ndjson", bytes);
        let _ = OcsfParser.parse_indexed_reader_report(
            "fuzz.ndjson",
            &mut std::io::Cursor::new(bytes),
            sha256(bytes),
            &CancellationToken::new(),
            &mut |_| Ok(()),
        );
    }
});
