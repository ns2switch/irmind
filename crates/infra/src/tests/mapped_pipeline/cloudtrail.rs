use super::*;
use irmind_domain::{CommonEventFilter, EntityRole, EventCategory, EventOutcome};

#[test]
fn bundled_cloudtrail_tables_survive_signed_ingestion_rebuild_and_v7_export() {
    let root = tempfile::tempdir().unwrap();
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(JsonSourceDecoder)],
            vec![Arc::new(
                irmind_mod_mapping_cloudtrail::CloudTrailMapping::new().unwrap(),
            )],
        )
        .unwrap(),
    );
    let (store, engine, catalog) = fixture_catalog(root.path(), catalog);
    let case = engine
        .create_case("Synthetic CloudTrail outcomes", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let cancel = CancellationToken::new();
    ingest(&large, &case.id, root.path(), &cancel);
    let filter = GraphQueryFilter::default().with_common(CommonEventFilter {
        category: Some(EventCategory::Authentication),
        outcome: Some(EventOutcome::Failure),
        ..CommonEventFilter::default()
    });
    let timeline = store.timeline_filtered(&case.id, &filter, 10).unwrap();
    assert_eq!(timeline.len(), 1);
    assert!(timeline[0].event.contains("ConsoleLogin"));
    let actor = filter.clone().with_common(CommonEventFilter {
        role: Some(EntityRole::Actor),
        ..filter.common()
    });
    assert!(
        store
            .entity_lookup_filtered(&case.id, &actor, "user", "alice")
            .unwrap()
            .contains("observations=1")
    );
    engine.verify(&case.id).unwrap();
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, root.path(), &cancel)
            .unwrap(),
        3
    );
    engine.seal(&case.id).unwrap();
    let target = root.path().join("cloudtrail.irmind");
    let key = irmind_app::export_case(&engine, store.as_ref(), &case.id, &target, &cancel).unwrap();
    assert_eq!(
        LocalExportVerifier
            .verify_export_details(&target, Some(&key))
            .unwrap()
            .format_version,
        7
    );
}

fn ingest(large: &LargeCaseUseCases<'_, '_>, id: &CaseId, root: &Path, cancel: &CancellationToken) {
    let base: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../testkit/fixtures/common/cloudtrail-console-login.jsonl"
    ))
    .unwrap();
    for (name, result) in [
        ("failure.json", Some("Failure")),
        ("success.json", Some("Success")),
        ("unknown.json", None),
    ] {
        let mut record = base.clone();
        record["responseElements"] = result.map_or(
            serde_json::Value::Null,
            |r| serde_json::json!({"ConsoleLogin":r}),
        );
        let bytes = serde_json::to_vec(&record).unwrap();
        fs::write(root.join(name), &bytes).unwrap();
        let selected = ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-source-v1".into(),
            confidence: 90,
            mode: ParserSelectionMode::Automatic,
            timestamp_context: None,
            format_sample_sha256: sha256(&bytes),
        };
        large
            .ingest_local_batch_selected(
                id,
                root,
                &[name.into()],
                false,
                &BTreeMap::from([(name.into(), selected)]),
                cancel,
            )
            .unwrap();
    }
}
