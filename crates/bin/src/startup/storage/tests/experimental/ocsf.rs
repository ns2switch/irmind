use super::*;
use irmind_app::EvidenceGraph;

#[test]
fn ocsf_detects_decodes_maps_filters_and_rebuilds_original_fields() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let registry = registry();
    let config = PersistentConfig::default();
    let catalog =
        super::super::super::experimental_parsers(registry.parser_catalog(), &config, &registry)
            .unwrap();
    let bytes = br#"{"time_dt":"2026-11-01T00:00:00.123456789Z","class_uid":3002,"category_uid":3,"activity_id":1,"status_id":2,"metadata":{"version":"1.4.0"},"device":{"hostname":"synthetic-host"},"actor":{"user":{"name":"alice","domain":"CORP-A"}},"src_endpoint":{"ip":"203.0.113.77"},"unmapped":"synthetic OCSF test"}"#;
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: "events.ndjson",
            sample: bytes,
            parser_override: None,
            forced: false,
            time_context: None,
            cluster_context: None,
        })
        .unwrap();
    assert_eq!(selected.selection.parser_version, "ocsf-source-v1");
    let store = super::super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic OCSF source mapping", "local only")
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

#[test]
fn malformed_seekable_source_is_rejected_without_discarding_other_sources() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let registry = registry();
    let config = PersistentConfig::default();
    let catalog =
        super::super::super::experimental_parsers(registry.parser_catalog(), &config, &registry)
            .unwrap();
    let good = br#"{"time":1793491200000,"class_uid":3002,"category_uid":3,"metadata":{"version":"1.4.0"}}"#;
    let bad = b"PAR1malformed source footer";
    let mut selections = BTreeMap::new();
    let mut parser = None;
    for (path, bytes) in [
        ("good.json", good.as_slice()),
        ("bad.parquet", bad.as_slice()),
    ] {
        std::fs::write(root.path().join(path), bytes).unwrap();
        let selected = catalog
            .select_source(ParserSelectionRequest {
                source: path,
                sample: bytes,
                parser_override: Some("parser-ocsf"),
                forced: true,
                time_context: None,
                cluster_context: None,
            })
            .unwrap();
        selections.insert(path.into(), selected.selection);
        parser = Some(selected.parser);
    }
    let store = super::super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic seekable rejection", "local only")
        .unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &store,
        parser: parser.as_ref().unwrap().as_ref(),
    };
    use_cases
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &["good.json".into(), "bad.parquet".into()],
            false,
            &selections,
            &CancellationToken::new(),
        )
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == irmind_domain::AuditEventKind::SourceManifestV2)
            .count(),
        1
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == irmind_domain::AuditEventKind::ToolError)
            .count(),
        1
    );
    engine.verify(&case.id).unwrap();
    let spool = root
        .path()
        .join("parquet")
        .join(case.id.as_str())
        .join("spool");
    assert_eq!(spool.read_dir().unwrap().count(), 0);
}
