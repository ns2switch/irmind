#![no_main]

use irmind_app::{
    CancellationToken, LogParser as _, SourceDecoder as _, SourceMapper as _, sha256,
};
use irmind_mod_parser_ecs::EcsParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 65_536 {
        let cancel = CancellationToken::new();
        if let (Ok(source), Ok(mapping)) = (
            irmind_app::source_mapping::SourceReferenceV1::file("fuzz.ndjson"),
            irmind_mod_mapping_ecs::EcsMapping::new(),
        ) {
            let _ = irmind_mod_parser_ecs::EcsSourceDecoder.decode_reader(
                irmind_app::source_mapping::SourceInput {
                    metadata: irmind_app::source_mapping::SourceMetadata {
                        source: &source,
                        evidence_hash: sha256(bytes),
                        time_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut std::io::Cursor::new(bytes),
                },
                &mut |row| {
                    row.inspect(|record| {
                        let _ = mapping.map(record);
                    });
                    Ok(())
                },
            );
        }
        let _ = EcsParser.detect("fuzz.ndjson", bytes);
    }
});
