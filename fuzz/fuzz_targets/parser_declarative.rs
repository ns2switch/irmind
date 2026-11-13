#![no_main]
use irmind_app::{CancellationToken, DefinitionCompiler as _, sha256};
use irmind_mod_parser_declarative::DeclarativeParser;
use libfuzzer_sys::fuzz_target;

const DEFINITIONS: [&str; 3] = [
    include_str!("../../docs/examples/parsers/access-csv.toml"),
    include_str!("../../docs/examples/parsers/nested-ndjson.toml"),
    include_str!("../../docs/examples/parsers/auth-regex.toml"),
];

fuzz_target!(|bytes: &[u8]| {
    let Some((&selector, data)) = bytes.split_first() else {
        return;
    };
    if data.len() > 1024 * 1024 {
        return;
    }
    if selector % 4 == 3 {
        if data.len() <= 65_536
            && let Ok(definition) = std::str::from_utf8(data)
        {
            let _ = DeclarativeParser::from_toml(definition);
        }
        return;
    }
    let Ok(parser) = DeclarativeParser::from_toml(DEFINITIONS[usize::from(selector % 3)]) else {
        return;
    };
    let _ = parser.detect_sample(data);
    if let Ok(pipeline) = irmind_mod_parser_declarative::DeclarativeCompiler
        .compile(DEFINITIONS[usize::from(selector % 3)])
    {
        let cancel = CancellationToken::new();
        let source =
            irmind_app::source_mapping::SourceReferenceV1::file("synthetic/fuzz.log").unwrap();
        let _ = pipeline.decoder().decode_reader(
            irmind_app::source_mapping::SourceInput {
                metadata: irmind_app::source_mapping::SourceMetadata {
                    source: &source,
                    evidence_hash: sha256(data),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(data),
            },
            &mut |row| {
                row.inspect(|source| {
                    let _ = pipeline.extraction_mapper().map(source);
                });
                Ok(())
            },
        );
    }
});
