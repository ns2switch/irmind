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
    let (store, engine) = source_fixture(root.path(), 75);
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
            .contains("observations=1")
    );
    assert_derived_hash_is_checked(&store, &case.id);
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

fn assert_derived_hash_is_checked(store: &LocalStore, id: &CaseId) {
    let active = irmind_app::artifact_catalog(&store.entries(id).unwrap())
        .unwrap()
        .active;
    let path = store.parquet.case_dir(id).unwrap().join(active[0].path());
    let original = fs::read(&path).unwrap();
    let mut changed = original.clone();
    changed[0] ^= 1;
    fs::write(&path, changed).unwrap();
    assert!(matches!(
        store.graph_summary(id),
        Err(AppError::EvidenceMismatch(_))
    ));
    fs::write(&path, original).unwrap();
    assert_eq!(store.timeline(id, 10).unwrap().len(), 2);
}
