use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn signed_source_and_artifact_survive_reopen_and_detect_source_change() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("inputs");
    fs::create_dir(&source_root).unwrap();
    let path = source_root.join("cloudtrail.json");
    fs::write(&path, br#"{"Records":[{"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.8"}]}"#).unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[71u8; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
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
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine
        .create_case("large case", "account 123456789012")
        .unwrap();
    let parquet = super::super::ParquetStore::open(root.path()).unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &parquet,
        parser: parser.as_ref(),
    };
    let hash = use_cases
        .ingest_local(
            &case.id,
            &source_root,
            "cloudtrail.json",
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        use_cases
            .ingest_local(
                &case.id,
                &source_root,
                "cloudtrail.json",
                false,
                &CancellationToken::new(),
            )
            .unwrap(),
        hash
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 4);
    let source_report = use_cases
        .verify_sources(
            &case.id,
            &source_root,
            SourceCheckMode::Full,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        (
            source_report.total,
            source_report.checked,
            source_report.unchecked
        ),
        (1, 1, 0)
    );
    assert!(source_report.missing_or_changed.is_empty());
    assert_eq!(
        use_cases
            .verify_parquet(&case.id, &CancellationToken::new())
            .unwrap(),
        2
    );
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, &source_root, &CancellationToken::new())
            .unwrap(),
        1
    );
    assert!(
        store
            .text_search(&case.id, "203.0.113.8", 10)
            .unwrap()
            .contains("AssumeRole")
    );
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 1);
    assert!(
        store
            .entity_lookup(&case.id, "ip", "203.0.113.8")
            .unwrap()
            .contains("count=1")
    );
    assert!(
        store
            .neighbors(&case.id, "ip", "203.0.113.8", 10)
            .unwrap()
            .contains("account")
    );
    assert!(
        store
            .entity_timeline(&case.id, "ip", "203.0.113.8", 10)
            .unwrap()
            .contains("AssumeRole")
    );
    assert!(
        store
            .raw_record(&case.id, hash.as_str(), 0)
            .unwrap()
            .contains("AssumeRole")
    );
    assert!(
        store
            .graph_summary(&case.id)
            .unwrap()
            .contains("Parquet records=1")
    );
    assert!(
        store
            .graph_path(&case.id, ("ip", "203.0.113.8"), ("account", "123456789012"))
            .unwrap()
            .contains("co-observed")
    );
    engine.seal(&case.id).unwrap();
    let manifest_only = root.path().join("manifest-only.irmind");
    irmind_app::export_case(
        &engine,
        store.as_ref(),
        &case.id,
        &manifest_only,
        &CancellationToken::new(),
    )
    .unwrap();
    let report = verify_export_details(&LocalExportVerifier, &manifest_only, None).unwrap();
    assert_eq!(
        (
            report.format_version,
            report.source_manifests,
            report.source_bytes_unavailable
        ),
        (4, 1, 1)
    );
    let with_original = root.path().join("with-original.irmind");
    irmind_app::export_case_v4(
        &engine,
        store.as_ref(),
        &case.id,
        &with_original,
        Some(&source_root),
        true,
        &CancellationToken::new(),
    )
    .unwrap();
    let report = verify_export_details(&LocalExportVerifier, &with_original, None).unwrap();
    assert_eq!(
        (
            report.source_bytes_verified,
            report.source_bytes_unavailable
        ),
        (1, 0)
    );
    let mut altered = fs::read(&with_original).unwrap();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    fs::write(&with_original, altered).unwrap();
    assert!(verify_export_details(&LocalExportVerifier, &with_original, None).is_err());
    fs::write(&path, b"changed").unwrap();
    let changed = use_cases
        .verify_sources(
            &case.id,
            &source_root,
            SourceCheckMode::Full,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(changed.missing_or_changed, vec![hash.as_str().to_owned()]);
    assert_eq!(engine.verify(&case.id).unwrap(), 5);
}

#[test]
fn parallel_batch_signs_sources_in_order_and_reuses_identical_artifact() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("inputs");
    fs::create_dir(&source_root).unwrap();
    let content = br#"{"eventTime":"2026-10-28T12:00:00Z","eventName":"ConsoleLogin"}"#;
    fs::write(source_root.join("b.json"), content).unwrap();
    fs::write(source_root.join("a.json"), content).unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[72u8; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
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
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine.create_case("batch", "account 123456789012").unwrap();
    let cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    let result = cases
        .ingest_local_batch(
            &case.id,
            &source_root,
            &["b.json".into(), "a.json".into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(result[0].0, "a.json");
    assert_eq!(result[1].0, "b.json");
    assert_eq!(result[0].1, result[1].1);
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::SourceManifestV1)
            .count(),
        2
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::ParquetArtifactV1)
            .count(),
        2
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 5);
    fs::write(source_root.join("a.json"), b"changed").unwrap();
    assert!(
        cases
            .ingest_local(
                &case.id,
                &source_root,
                "a.json",
                false,
                &CancellationToken::new(),
            )
            .is_err()
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 5);
}
