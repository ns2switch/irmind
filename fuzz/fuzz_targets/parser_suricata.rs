#![no_main]
use irmind_app::{
    CancellationToken, LogParser as _, SourceDecoder as _, SourceMapper as _, sha256,
};
use irmind_mod_parser_suricata::SuricataParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        static MAPPER: std::sync::OnceLock<irmind_mod_mapping_network::NetworkMapping> =
            std::sync::OnceLock::new();
        let mapper = MAPPER.get_or_init(|| {
            irmind_mod_mapping_network::NetworkMapping::new("parser-suricata")
                .expect("bundled mapping")
        });
        let source =
            irmind_app::source_mapping::SourceReferenceV1::file("fuzz.log").expect("fixed source");
        let cancel = CancellationToken::new();
        let _ = irmind_mod_parser_suricata::SuricataSourceDecoder.decode_reader(
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
            &mut |record| {
                record.inspect(|source| {
                    let _ = mapper.map(source);
                });
                Ok(())
            },
        );

        let _ = SuricataParser.detect("fuzz.jsonl", bytes);
    }
});
