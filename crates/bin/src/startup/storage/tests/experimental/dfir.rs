use super::*;
use irmind_app::EvidenceGraph;

fn dfir_registry() -> ModuleRegistry {
    let mut registry = registry();
    for parser in [
        Box::new(irmind_mod_parser_velociraptor::VelociraptorParser)
            as Box<dyn irmind_app::modules::Module>,
        Box::new(irmind_mod_parser_hayabusa::HayabusaParser),
        Box::new(irmind_mod_parser_chainsaw::ChainsawParser),
        Box::new(irmind_mod_parser_plaso::PlasoParser),
        Box::new(irmind_mod_parser_eztools::EztoolsParser),
    ] {
        registry.register(parser, &ModuleConfig::new()).unwrap();
    }
    for mapper in irmind_mod_mapping_dfir::DfirExtractionMapping::all().unwrap() {
        registry
            .register(Box::new(mapper), &ModuleConfig::new())
            .unwrap();
    }
    registry
}
fn fixtures() -> [(&'static str, &'static str, &'static [u8]); 5] {
    [
        (
            "parser-velociraptor",
            "velociraptor.jsonl",
            include_bytes!(
                "../../../../../../testkit/fixtures/parser-velociraptor/source/events.jsonl"
            ),
        ),
        (
            "parser-hayabusa",
            "hayabusa.jsonl",
            include_bytes!(
                "../../../../../../testkit/fixtures/parser-hayabusa/source/events.jsonl"
            ),
        ),
        (
            "parser-chainsaw",
            "chainsaw.jsonl",
            include_bytes!(
                "../../../../../../testkit/fixtures/parser-chainsaw/source/events.jsonl"
            ),
        ),
        (
            "parser-plaso",
            "plaso.jsonl",
            include_bytes!("../../../../../../testkit/fixtures/parser-plaso/source/events.jsonl"),
        ),
        (
            "parser-eztools",
            "eztools.csv",
            include_bytes!("../../../../../../testkit/fixtures/parser-eztools/source/events.csv"),
        ),
    ]
}
#[test]
fn dfir_sources_are_selected_mapped_signed_and_reproducibly_rebuilt() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let registry = dfir_registry();
    let config = PersistentConfig::default();
    let catalog =
        super::super::super::experimental_parsers(registry.parser_catalog(), &config, &registry)
            .unwrap();
    let store = super::super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic DFIR extraction", "local only")
        .unwrap();
    for (parser, path, bytes) in fixtures() {
        let selected = catalog
            .select_source(ParserSelectionRequest {
                source: path,
                sample: bytes,
                parser_override: Some(parser),
                forced: true,
                time_context: None,
                cluster_context: None,
            })
            .unwrap();
        assert!(selected.selection.parser_version.ends_with("-source-v1"));
        std::fs::write(root.path().join(path), bytes).unwrap();
        LargeCaseUseCases {
            engine: &engine,
            store: &store,
            parser: selected.parser.as_ref(),
        }
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &[path.into()],
            false,
            &BTreeMap::from([(path.into(), selected.selection)]),
            &CancellationToken::new(),
        )
        .unwrap();
    }
    assert_eq!(store.timeline(&case.id, 100).unwrap().len(), 10);
    let parser = catalog.get("parser-plaso").unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &store,
        parser: parser.as_ref(),
    };
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
            .unwrap(),
        5
    );
    engine.verify(&case.id).unwrap();
    let entries = store.entries(&case.id).unwrap();
    assert!(
        irmind_app::artifact_catalog(&entries)
            .unwrap()
            .active
            .iter()
            .all(|a| matches!(a, ParquetArtifact::V3(_)))
    );
}
