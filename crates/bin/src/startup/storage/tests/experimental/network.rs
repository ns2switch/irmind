use super::*;
use irmind_app::EvidenceGraph;

#[test]
fn original_network_sources_keep_uid_flow_and_precise_time_through_signed_rebuild() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let registry = network_registry();
    let config = PersistentConfig::default();
    let catalog =
        super::super::super::experimental_parsers(registry.parser_catalog(), &config, &registry)
            .unwrap();
    let store = super::super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic network sources", "local only")
        .unwrap();
    for (parser, path, bytes) in fixtures() {
        std::fs::write(root.path().join(path), bytes).unwrap();
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
    assert_eq!(store.timeline(&case.id, 100).unwrap().len(), 5);
    assert!(
        store
            .entity_lookup(&case.id, "uid", "CsyntheticZeek1")
            .unwrap()
            .contains("CsyntheticZeek1")
    );
    assert!(
        store
            .entity_lookup(&case.id, "flow", "9001001")
            .unwrap()
            .contains("9001001")
    );
    let parser = catalog.get("parser-zeek").unwrap();
    assert_eq!(
        LargeCaseUseCases {
            engine: &engine,
            store: &store,
            parser: parser.as_ref()
        }
        .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
        .unwrap(),
        3
    );
    engine.verify(&case.id).unwrap();
}
fn fixtures() -> [(&'static str, &'static str, &'static [u8]); 3] {
    [
        (
            "parser-zeek",
            "conn.log",
            include_bytes!("../../../../../../testkit/fixtures/parser-zeek/source/events.log"),
        ),
        (
            "parser-zeek",
            "dns.jsonl",
            include_bytes!("../../../../../../testkit/fixtures/parser-zeek/source/dns.jsonl"),
        ),
        (
            "parser-suricata",
            "eve.jsonl",
            include_bytes!("../../../../../../testkit/fixtures/parser-suricata/source/eve.jsonl"),
        ),
    ]
}

fn network_registry() -> ModuleRegistry {
    let mut registry = registry();
    registry
        .register(
            Box::new(irmind_mod_parser_zeek::ZeekParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .register(
            Box::new(irmind_mod_parser_suricata::SuricataParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    for mapper in irmind_mod_mapping_network::NetworkMapping::all().unwrap() {
        registry
            .register(Box::new(mapper), &ModuleConfig::new())
            .unwrap();
    }
    registry
}
