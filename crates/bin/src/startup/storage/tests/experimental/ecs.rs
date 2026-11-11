use super::*;
use irmind_app::EvidenceGraph;

#[test]
fn ecs_detects_decodes_maps_filters_and_rebuilds_original_fields() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let registry = registry();
    let config = PersistentConfig::default();
    let catalog =
        super::super::super::experimental_parsers(registry.parser_catalog(), &config, &registry)
            .unwrap();
    let bytes = br#"{"@timestamp":"2026-11-01T00:00:00.123456789Z","ecs":{"version":"9.5.0"},"event":{"category":["authentication"],"type":["start"],"outcome":"failure"},"host":{"name":"synthetic-host"},"user":{"name":"alice","domain":"CORP-A"},"source":{"ip":"203.0.113.77"},"message":"synthetic ECS test"}"#;
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: "events.ndjson",
            sample: bytes,
            parser_override: None,
            forced: false,
            time_context: None,
        })
        .unwrap();
    assert_eq!(selected.selection.parser_version, "ecs-source-v1");
    let store = super::super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic ECS source mapping", "local only")
        .unwrap();
    std::fs::write(root.path().join("events.ndjson"), bytes).unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &store,
        parser: selected.parser.as_ref(),
    };
    use_cases
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &["events.ndjson".into()],
            false,
            &BTreeMap::from([("events.ndjson".into(), selected.selection)]),
            &CancellationToken::new(),
        )
        .unwrap();
    let failure = irmind_app::GraphQueryFilter::from_args(&BTreeMap::from([
        ("event_category".into(), "authentication".into()),
        ("event_outcome".into(), "failure".into()),
    ]))
    .unwrap();
    assert_eq!(
        store
            .timeline_filtered(&case.id, &failure, 10)
            .unwrap()
            .len(),
        1
    );
    let success = irmind_app::GraphQueryFilter::from_args(&BTreeMap::from([(
        "event_outcome".into(),
        "success".into(),
    )]))
    .unwrap();
    assert!(
        store
            .timeline_filtered(&case.id, &success, 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .entity_lookup(&case.id, "user", "alice")
            .unwrap()
            .contains("alice")
    );
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
            .unwrap(),
        1
    );
    engine.verify(&case.id).unwrap();
}
