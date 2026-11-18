#![no_main]
use irmind_app::source_mapping::{
    SourceInput, SourceMapper as _, SourceMetadata, SourceReferenceV1,
};
use irmind_app::{CancellationToken, LogParser as _, SourceDecoder as _, sha256};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4_194_304 {
        return;
    }
    static MAPPERS: OnceLock<irmind_mod_mapping_defender::DefenderMapping> = OnceLock::new();
    let mappers = MAPPERS
        .get_or_init(|| irmind_mod_mapping_defender::DefenderMapping::new().expect("included mappings"));
    let source = SourceReferenceV1::file("fuzz.ndjson").expect("fixed source");
    let cancel = CancellationToken::new();
    let _ = irmind_mod_parser_defender::DefenderParser.detect("fuzz.ndjson", bytes);
    let _ = irmind_mod_parser_defender::DefenderSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
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
                for mapper in [mappers] {
                    if mapper
                        .manifest()
                        .selectors()
                        .iter()
                        .any(|selector| selector.matches(source))
                    {
                        let _ = mapper.map(source);
                    }
                }
            });
            Ok(())
        },
    );
});
