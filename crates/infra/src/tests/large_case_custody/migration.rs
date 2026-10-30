use super::*;

#[test]
fn missing_legacy_original_keeps_a_verified_read_only_chain() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[79u8; 32]),
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
    let id = engine.create_case("Old case", "local").unwrap().id;
    let bytes = br#"{"eventName":"AssumeRole"}"#;
    let hash = ingest_historical_fixture(store.as_ref(), signer.as_ref(), &id, bytes, "old.json");
    fs::remove_file(root.path().join("evidence").join(hash)).unwrap();
    assert!(engine.verify(&id).is_err());
    assert_eq!(
        engine
            .inspect_signed_chain_only(&id, &CancellationToken::new())
            .unwrap(),
        3
    );
    assert!(store.graph_summary(&id).is_err());
    assert!(
        LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: parser.as_ref()
        }
        .migrate_legacy(&id, &CancellationToken::new())
        .is_err()
    );
}

#[test]
fn open_legacy_case_migrates_with_verified_chain_and_v4_export() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[73u8; 32]),
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
        .create_case("legacy", "account 123456789012")
        .unwrap();
    let bytes = br#"{"eventTime":"2026-10-28T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.9"}"#;
    ingest_historical_fixture(
        store.as_ref(),
        signer.as_ref(),
        &case.id,
        bytes,
        "legacy.json",
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 3);
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    assert_eq!(
        use_cases
            .migrate_legacy_open(&case.id, &CancellationToken::new())
            .unwrap(),
        1
    );
    assert_eq!(
        use_cases
            .migrate_legacy_open(&case.id, &CancellationToken::new())
            .unwrap(),
        0
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 5);
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
            .unwrap(),
        1
    );
    assert!(
        store
            .text_search(&case.id, "203.0.113.9", 10)
            .unwrap()
            .contains("ConsoleLogin")
    );
    engine.seal(&case.id).unwrap();
    let path = root.path().join("migrated.irmind");
    irmind_app::export_case(
        &engine,
        store.as_ref(),
        &case.id,
        &path,
        &CancellationToken::new(),
    )
    .unwrap();
    let report = verify_export_details(&LocalExportVerifier, &path, None).unwrap();
    assert_eq!(report.format_version, 4);
    assert_eq!(report.source_manifests, 0);
    assert_eq!(report.source_bytes_unavailable, 0);
}

#[test]
#[allow(clippy::too_many_lines)]
fn sealed_legacy_migration_keeps_the_seal_and_exports_signed_operations() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[74u8; 32]),
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
        .create_case("sealed legacy", "account 123456789012")
        .unwrap();
    ingest_historical_fixture(store.as_ref(), signer.as_ref(),
        &case.id,
        br#"{"eventTime":"2026-10-28T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.9"}"#,
        "legacy.json",
    );
    engine.seal(&case.id).unwrap();
    let original_seal = store.case_seal(&case.id).unwrap().unwrap();
    let original_entries = engine.verify(&case.id).unwrap();
    assert!(store.graph_summary(&case.id).is_err());
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    assert_eq!(
        use_cases
            .migrate_legacy(&case.id, &CancellationToken::new())
            .unwrap(),
        1
    );
    assert_eq!(
        use_cases
            .migrate_legacy(&case.id, &CancellationToken::new())
            .unwrap(),
        0
    );
    assert_eq!(engine.verify(&case.id).unwrap(), original_entries);
    assert_eq!(
        store.case_seal(&case.id).unwrap().unwrap().hash,
        original_seal.hash
    );
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
            .unwrap(),
        1
    );
    assert!(
        store
            .text_search(&case.id, "203.0.113.9", 10)
            .unwrap()
            .contains("ConsoleLogin")
    );
    let package = root.path().join("sealed-migrated.irmind");
    irmind_app::export_case_v4(
        &engine,
        store.as_ref(),
        &case.id,
        &package,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(
        verify_export_details(&LocalExportVerifier, &package, None)
            .unwrap()
            .format_version,
        4
    );
    let bytes = fs::read(&package).unwrap();
    let marker = b"sealed-parquet-artifact-v1:";
    let offset = bytes
        .windows(marker.len())
        .position(|part| part == marker)
        .unwrap();
    let mut changed = bytes;
    changed[offset + marker.len() - 2] = b'2';
    let tampered = root.path().join("tampered.irmind");
    fs::write(&tampered, changed).unwrap();
    assert!(verify_export_details(&LocalExportVerifier, &tampered, None).is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn signed_bundles_replace_base_files_for_queries_and_rebuild_exactly() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("sources");
    fs::create_dir(&source_root).unwrap();
    for (name, ip) in [("a.json", "203.0.113.10"), ("b.json", "203.0.113.11")] {
        fs::write(source_root.join(name), format!(
            "{{\"eventTime\":\"2026-10-28T12:00:00Z\",\"eventName\":\"ConsoleLogin\",\"sourceIPAddress\":\"{ip}\"}}"
        )).unwrap();
    }
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[75u8; 32]),
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
        .create_case("bundles", "account 123456789012")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    large
        .ingest_local_batch(
            &case.id,
            &source_root,
            &["b.json".into(), "a.json".into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 2);
    assert_eq!(
        large
            .compact_case(&case.id, &CancellationToken::new())
            .unwrap(),
        2
    );
    assert_eq!(
        large
            .compact_case(&case.id, &CancellationToken::new())
            .unwrap(),
        0
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 9);
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, &source_root, &CancellationToken::new())
            .unwrap(),
        2
    );
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 2);
    assert!(
        store
            .text_search(&case.id, "203.0.113.10", 10)
            .unwrap()
            .contains("ConsoleLogin")
    );
    assert!(
        store
            .entity_lookup(&case.id, "ip", "203.0.113.10")
            .unwrap()
            .contains("count=1")
    );
    let external = rusqlite::Connection::open(root.path().join("irmind.db")).unwrap();
    external
        .execute_batch("DROP TRIGGER audit_no_update")
        .unwrap();
    external
        .execute(
            "UPDATE audit SET payload='tampered' WHERE case_id=?1 AND seq=1",
            [case.id.as_str()],
        )
        .unwrap();
    assert!(store.graph_summary(&case.id).is_err());
    assert!(engine.verify(&case.id).is_err());
}
