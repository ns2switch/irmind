#[test]
fn operational_cancellation_preserves_a_sealed_case_and_is_verified() {
    let root = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = std::sync::Arc::new(TestSigner {
        key: SigningKey::from_bytes(&[116u8; 32]),
        actor: Actor::Analyst,
    });
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(), store.clone(), store.clone(), store.clone(),
            CryptoPorts::new(signer.clone(), std::sync::Arc::new(LocalVerifier::from_signer(signer.as_ref()))),
            std::sync::Arc::new(MandatoryGuard::new().unwrap()),
            std::sync::Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        std::sync::Arc::new(SystemClock),
    ).unwrap();
    let case = engine.create_case("Cancelled verify", "local only").unwrap();
    let preview = engine.prepare_seal(&case.id).unwrap();
    let expected_hash = preview.final_hash();
    assert_eq!(preview.entry_count(), 2);
    engine.seal_prepared(&preview).unwrap();
    let sealed_entries = store.entries(&case.id).unwrap();
    let sealed_hash = sealed_entries.last().unwrap().hash;
    assert_eq!(sealed_hash, expected_hash);
    engine.record_cancellation(&case.id, irmind_app::CancelledOperation::Verify).unwrap();
    assert_eq!(store.entries(&case.id).unwrap().len(), sealed_entries.len());
    assert_eq!(store.entries(&case.id).unwrap().last().unwrap().hash, sealed_hash);
    assert_eq!(store.operations(&case.id).unwrap().len(), 1);
    engine.verify(&case.id).unwrap();

    let db = store.conn().unwrap();
    db.execute_batch("DROP TRIGGER operational_audit_no_update").unwrap();
    db.execute("UPDATE operational_audit SET operation='other' WHERE case_id=?1", [case.id.as_str()]).unwrap();
    drop(db);
    assert!(matches!(engine.verify(&case.id), Err(AppError::InvalidChain(1))));
}

#[test]
fn seal_preview_rejects_a_changed_case() {
    let root = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = std::sync::Arc::new(TestSigner {
        key: SigningKey::from_bytes(&[117u8; 32]), actor: Actor::Analyst,
    });
    let engine = Engine::new(
        EnginePorts::new(store.clone(), store.clone(), store.clone(), store.clone(),
            CryptoPorts::new(signer.clone(), std::sync::Arc::new(LocalVerifier::from_signer(signer.as_ref()))),
            std::sync::Arc::new(MandatoryGuard::new().unwrap()), std::sync::Arc::new(JsonParser)),
        ExecutionMode::Attended, std::sync::Arc::new(SystemClock),
    ).unwrap();
    let case = engine.create_case("Preview", "local only").unwrap();
    let preview = engine.prepare_seal(&case.id).unwrap();
    engine.change_scope(&case.id, "local revised").unwrap();
    assert!(engine.seal_prepared(&preview).is_err());
    assert!(!store.get_case(&case.id).unwrap().sealed);
}
