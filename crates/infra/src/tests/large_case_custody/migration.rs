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
#[allow(clippy::too_many_lines)]
fn retired_reader_cannot_reinterpret_open_or_sealed_history_but_exports_still_verify() {
    for sealed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[73; 32]),
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
            .create_case("Legacy authenticated history", "local only")
            .unwrap();
        ingest_historical_fixture(store.as_ref(), signer.as_ref(), &case.id, br#"{"eventTime":"2026-10-28T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.9"}"#, "legacy.json");
        if sealed {
            engine.seal(&case.id).unwrap();
        }
        let before = store.entries(&case.id).unwrap();
        let before_seal = store.case_seal(&case.id).unwrap();
        let before_operations = store.operations(&case.id).unwrap().len();
        let large = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &JsonParser,
        };
        assert!(
            large
                .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
                .is_err()
        );
        let error = large
            .migrate_legacy(&case.id, &CancellationToken::new())
            .unwrap_err();
        assert!(error.to_string().contains("create a new case"));
        assert_eq!(
            store
                .entries(&case.id)
                .unwrap()
                .iter()
                .map(|e| e.hash)
                .collect::<Vec<_>>(),
            before.iter().map(|e| e.hash).collect::<Vec<_>>()
        );
        assert_eq!(
            store.case_seal(&case.id).unwrap().map(|s| s.hash),
            before_seal.map(|s| s.hash)
        );
        assert_eq!(store.operations(&case.id).unwrap().len(), before_operations);
        assert_eq!(engine.verify(&case.id).unwrap(), before.len());
        if !sealed {
            engine.seal(&case.id).unwrap();
        }
        let path = root.path().join("legacy.irmind");
        irmind_app::export_case(
            &engine,
            store.as_ref(),
            &case.id,
            &path,
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(
            verify_export_details(&LocalExportVerifier, &path, None)
                .unwrap()
                .format_version,
            3
        );
        let mut tampered = fs::read(&path).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(verify_export_details(&LocalExportVerifier, &path, None).is_err());
    }
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
        3
    );
    assert_eq!(
        large
            .compact_case(&case.id, &CancellationToken::new())
            .unwrap(),
        0
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 12);
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
