use super::*;
use irmind_app::SourceDecoder;

pub(super) fn fixtures() -> Vec<(&'static str, Arc<dyn SourceDecoder>, &'static [u8])> {
    vec![
        (
            "parser-velociraptor",
            Arc::new(irmind_mod_parser_velociraptor::VelociraptorSourceDecoder),
            include_bytes!("../../../testkit/fixtures/parser-velociraptor/source/events.jsonl"),
        ),
        (
            "parser-hayabusa",
            Arc::new(irmind_mod_parser_hayabusa::HayabusaSourceDecoder),
            include_bytes!("../../../testkit/fixtures/parser-hayabusa/source/events.jsonl"),
        ),
        (
            "parser-chainsaw",
            Arc::new(irmind_mod_parser_chainsaw::ChainsawSourceDecoder),
            include_bytes!("../../../testkit/fixtures/parser-chainsaw/source/events.jsonl"),
        ),
        (
            "parser-plaso",
            Arc::new(irmind_mod_parser_plaso::PlasoSourceDecoder),
            include_bytes!("../../../testkit/fixtures/parser-plaso/source/events.jsonl"),
        ),
        (
            "parser-eztools",
            Arc::new(irmind_mod_parser_eztools::EztoolsSourceDecoder),
            include_bytes!("../../../testkit/fixtures/parser-eztools/source/events.csv"),
        ),
    ]
}
#[test]
fn source_and_extraction_bytes_are_independent_of_json_map_features() {
    let actual = fixtures()
        .into_iter()
        .map(|(name, decoder, bytes)| {
            let mapper = irmind_mod_mapping_dfir::DfirExtractionMapping::new(name).unwrap();
            (
                name,
                super::source_pipeline_goldens::digest(decoder.as_ref(), &mapper, bytes, 2),
            )
        })
        .collect::<Vec<_>>();
    let expected = [
        (
            "parser-velociraptor",
            "31566a4be94f0d4e4b2e13a92e9995e08c27a37009770e0980887ec479d88a93",
        ),
        (
            "parser-hayabusa",
            "8b58a447794481a0de182534a96437a51091042c58877d25e5dba7cb93059cee",
        ),
        (
            "parser-chainsaw",
            "445eee2f9008ce4d7bc9e5ae6b99155799c5df4ab95440f4f657cab819fb9c2d",
        ),
        (
            "parser-plaso",
            "20d0cc31a38110bf6923ee16cf940891675159e9522f23207dbfd9e441d8a78b",
        ),
        (
            "parser-eztools",
            "57f9d289acae0ce889906d7d322e0e4346211114bb947c1738b57c29df742aad",
        ),
    ];
    assert_eq!(
        actual,
        expected
            .into_iter()
            .map(|(name, hash)| (name, hash.to_owned()))
            .collect::<Vec<_>>()
    );
}
