use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn failed_artifact_insert_rolls_back_the_source_manifest() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("sources");
    fs::create_dir(&source_root).unwrap();
    fs::write(
        source_root.join("cloudtrail.json"),
        br#"{"Records":[{"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012"},{"eventTime":"2026-10-29T12:00:00Z","eventName":"ConsoleLogin","recipientAccountId":"123456789012"}]}"#,
    )
    .unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[79; 32]),
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
        .create_case("atomic source", "account 123456789012")
        .unwrap();
    let baseline = engine.verify(&case.id).unwrap();
    let external = rusqlite::Connection::open(root.path().join("irmind.db")).unwrap();
    external
        .execute_batch(
            "CREATE TRIGGER reject_parquet_for_test BEFORE INSERT ON audit
         WHEN NEW.kind='ParquetArtifactV1'
         BEGIN SELECT RAISE(ABORT, 'simulated artifact failure'); END;",
        )
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    assert!(
        large
            .ingest_local(
                &case.id,
                &source_root,
                "cloudtrail.json",
                false,
                &CancellationToken::new()
            )
            .is_err()
    );
    assert_eq!(engine.verify(&case.id).unwrap(), baseline);
    assert!(store.entries(&case.id).unwrap().iter().all(|entry| {
        !matches!(
            entry.kind,
            AuditEventKind::SourceManifestV1 | AuditEventKind::ParquetArtifactV1
        )
    }));
    external
        .execute_batch("DROP TRIGGER reject_parquet_for_test")
        .unwrap();
    large
        .ingest_local(
            &case.id,
            &source_root,
            "cloudtrail.json",
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(engine.verify(&case.id).unwrap() > baseline + 2);
}
