//! The source decoder, mapper, writer and signed activation use one pipeline.
use super::*;
use irmind_app::source_mapping::MappingCatalog;
use irmind_app::{LargeCaseUseCases, ParserSelection, SourceDecoder};
use irmind_domain::{AuditEventKind, GraphQueryFilter, ParquetArtifact, ParserSelectionMode};
use irmind_mod_mapping_json_compat::JsonCompatibilityMapping;
use irmind_mod_parser_json::JsonSourceDecoder;

#[test]
#[allow(clippy::too_many_lines)]
fn mapped_pipeline_binds_raw_inputs_and_maps_before_writing_and_exporting() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let case = engine
        .create_case("Source mapping pipeline", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", JsonSourceDecoder.identity().version)
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let cancel = CancellationToken::new();
    for (name, second) in [("a.json", "01"), ("b.json", "02")] {
        let raw = format!(
            "{{\"eventTime\":\"2026-11-01T00:00:{second}.123456789Z\",\"eventName\":\"Login\",\"recipientAccountId\":\"123456789012\",\"awsRegion\":\"eu-west-1\",\"sourceIPAddress\":\"203.0.113.77\"}}"
        );
        fs::write(root.path().join(name), &raw).unwrap();
        let selected = ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-source-v1".into(),
            confidence: 90,
            mode: ParserSelectionMode::Automatic,
            timestamp_context: None,
            format_sample_sha256: sha256(raw.as_bytes()),
        };
        large
            .ingest_local_batch_selected(
                &case.id,
                root.path(),
                &[name.into()],
                true,
                &BTreeMap::from([(name.into(), selected)]),
                &cancel,
            )
            .unwrap();
    }
    let entries = store.entries(&case.id).unwrap();
    let artifacts = irmind_app::artifact_catalog(&entries).unwrap();
    assert!(
        artifacts
            .all
            .iter()
            .all(|a| matches!(a, ParquetArtifact::V3(_)))
    );
    assert_eq!(artifacts.all.len(), 6);
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::SourceRecordSetV1)
            .count(),
        2
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::MappingRunV1)
            .count(),
        2
    );
    // The second source reuses the exact earlier snapshot rather than copying it.
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::MappingProfileV1)
            .count(),
        3
    );
    engine.verify(&case.id).unwrap();
    assert_eq!(large.compact_case(&case.id, &cancel).unwrap(), 3);
    assert_eq!(large.verify_parquet(&case.id, &cancel).unwrap(), 9);
    assert!(
        store
            .entity_lookup(&case.id, "ip", "203.0.113.77")
            .unwrap()
            .contains("observations=2")
    );
    let timeline = store
        .timeline_filtered(&case.id, &GraphQueryFilter::default(), 20)
        .unwrap();
    assert_eq!(timeline.len(), 2);
    assert!(timeline[0].at.contains("123456789"));
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, root.path(), &cancel)
            .unwrap(),
        2
    );
    engine.seal(&case.id).unwrap();
    let path = root.path().join("mapped-pipeline.irmind");
    let key = irmind_app::export_case(&engine, store.as_ref(), &case.id, &path, &cancel).unwrap();
    assert_eq!(
        LocalExportVerifier
            .verify_export_details(&path, Some(&key))
            .unwrap()
            .format_version,
        6
    );
    let spool = store.parquet.case_dir(&case.id).unwrap().join("spool");
    assert_eq!(fs::read_dir(spool).unwrap().count(), 0);
}

#[test]
fn mapped_store_preserves_the_published_route_without_a_registered_raw_decoder() {
    use irmind_app::{LargeCaseStore, LocalBatchRequest};
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("event.json"),
        br#"{"eventTime":"2026-11-01T00:00:00Z","user":"synthetic"}"#,
    )
    .unwrap();
    fs::create_dir(root.path().join("mapped")).unwrap();
    fs::create_dir(root.path().join("legacy")).unwrap();
    let mapped = ParquetStore::open_mapped(
        &root.path().join("mapped"),
        Arc::new(MappingCatalog::default()),
    )
    .unwrap();
    let legacy = ParquetStore::open_precise(&root.path().join("legacy")).unwrap();
    let id = CaseId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    let run = |store: &ParquetStore| {
        store
            .prepare_local_batch(
                LocalBatchRequest {
                    case_id: &id,
                    source_root: &source,
                    relative_paths: &["event.json".into()],
                    copy_original: false,
                    parser: &JsonParser,
                    committed_artifacts: &[],
                    limits: irmind_app::PartitionLimits::default(),
                },
                &CancellationToken::new(),
            )
            .unwrap()
            .pop()
            .unwrap()
    };
    let first = run(&mapped);
    let second = run(&legacy);
    assert_eq!(first.artifacts, second.artifacts);
    assert!(first.mapping.is_none());
    assert!(second.mapping.is_none());
}

fn fixture<'a>(root: &Path) -> (Arc<LocalStore>, Engine<'a>, Arc<MappingCatalog>) {
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(JsonSourceDecoder)],
            vec![Arc::new(JsonCompatibilityMapping::new().unwrap())],
        )
        .unwrap(),
    );
    let store = Arc::new(LocalStore::open_mapped(root, catalog.clone()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[88; 32]),
        actor: Actor::Analyst,
    });
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    (store, engine, catalog)
}

mod repeat;

mod guard;
