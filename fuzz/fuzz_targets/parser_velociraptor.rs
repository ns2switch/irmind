#![no_main]
use irmind_app::{CancellationToken, LogParser as _, SourceDecoder as _, sha256};
use irmind_mod_parser_velociraptor::VelociraptorParser;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let source =
            irmind_app::source_mapping::SourceReferenceV1::file("fuzz.log").expect("fixed source");
        let cancel = CancellationToken::new();
        let _ = irmind_mod_parser_velociraptor::VelociraptorSourceDecoder.decode_reader(
            irmind_app::source_mapping::SourceInput {
                metadata: irmind_app::source_mapping::SourceMetadata {
                    source: &source,
                    evidence_hash: sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |_| Ok(()),
        );
        let _ = VelociraptorParser.detect("fuzz.log", bytes);
    }
});
