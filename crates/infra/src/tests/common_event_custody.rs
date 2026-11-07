use super::*;
use irmind_app::{LargeCaseStore, LargeCaseUseCases, ParserSelection};
use irmind_domain::{ParquetArtifact, ParserSelectionMode};

#[test]
#[allow(clippy::too_many_lines)]
fn common_bridge_has_signed_lineage_public_v5_verification_and_reconstruction() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open_common(root.path()).unwrap());
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
    let case = engine
        .create_case("Common event bridge", "local only")
        .unwrap();
    let raw = br#"{"eventTime":"2026-11-01T00:00:00.123456789Z","eventName":"Failed is original text","sourceIPAddress":"203.0.113.77"}"#;
    fs::write(root.path().join("events.json"), raw).unwrap();
    let selection = ParserSelection {
        parser_id: "parser-json".into(),
        parser_version: "json-stream-v3".into(),
        confidence: 90,
        mode: ParserSelectionMode::Automatic,
        timestamp_context: None,
        format_sample_sha256: sha256(raw),
    };
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    };
    large
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &["events.json".into()],
            true,
            &BTreeMap::from([("events.json".into(), selection)]),
            &CancellationToken::new(),
        )
        .unwrap();
    let catalog = irmind_app::artifact_catalog(&store.entries(&case.id).unwrap()).unwrap();
    assert_eq!(catalog.active.len(), 3);
    assert!(
        catalog
            .active
            .iter()
            .all(|a| matches!(a,ParquetArtifact::V2(v) if v.schema.is_common()))
    );
    assert!(engine.verify(&case.id).is_ok());
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
            .unwrap(),
        1
    );
    let unknown = irmind_app::GraphQueryFilter::from_args(&BTreeMap::from([(
        "event_outcome".into(),
        "unknown".into(),
    )]))
    .unwrap();
    let failure = irmind_app::GraphQueryFilter::from_args(&BTreeMap::from([(
        "event_outcome".into(),
        "failure".into(),
    )]))
    .unwrap();
    assert_eq!(
        store
            .timeline_filtered(&case.id, &unknown, 10)
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .timeline_filtered(&case.id, &failure, 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .text_search_filtered(&case.id, &failure, "Failed", 10)
            .unwrap()
            .contains("Schema coverage")
    );
    engine.seal(&case.id).unwrap();
    let path = root.path().join("common.irmind");
    let key = CaseExporter::export_case(store.as_ref(), &case.id, &path, &CancellationToken::new())
        .unwrap();
    let verified =
        irmind_app::verify_export_details(&LocalExportVerifier, &path, Some(&key)).unwrap();
    assert_eq!(verified.format_version, 5);
    assert!(
        irmind_app::verify_export_details(&LocalExportVerifier, &path, Some(&"00".repeat(32)))
            .is_err()
    );
    let artifact = catalog.active.iter().find(|a| matches!(a,ParquetArtifact::V2(v) if v.schema == irmind_domain::ArtifactSchemaV2::CommonEvents)).unwrap();
    let file = root
        .path()
        .join("parquet")
        .join(case.id.as_str())
        .join(artifact.path());
    let mut bytes = fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(file, bytes).unwrap();
    assert!(
        store
            .verify_artifact(&case.id, artifact, &CancellationToken::new())
            .is_err()
    );
    assert!(store.timeline(&case.id, 10).is_err());
}
