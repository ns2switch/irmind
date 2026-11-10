use super::*;

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
    let store = Arc::new(open_source_store(root.path()).unwrap());
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
        parser: &json_source_parser(),
    };
    for name in ["a.json", "b.json"] {
        large
            .ingest_local(
                &case.id,
                &source_root,
                name,
                false,
                &CancellationToken::new(),
            )
            .unwrap();
    }
    let before = engine.verify(&case.id).unwrap();
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 2);
    assert_eq!(
        large
            .compact_case_with_threshold(&case.id, 2, &CancellationToken::new())
            .unwrap(),
        3
    );
    assert_eq!(
        large
            .compact_case_with_threshold(&case.id, 2, &CancellationToken::new())
            .unwrap(),
        0
    );
    assert_eq!(engine.verify(&case.id).unwrap(), before + 6);
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
