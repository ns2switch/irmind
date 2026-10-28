use super::*;

fn fixture() -> (tempfile::TempDir, Arc<LocalStore>, Engine<'static>, CaseId) {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[61u8; 32]),
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
        .create_case("Incremental custody", "local evidence only")
        .unwrap();
    for index in 0..2 {
        let bytes =
            format!(r#"{{"eventTime":"2026-10-27T12:00:00Z","eventName":"Synthetic{index}"}}"#);
        engine
            .ingest(
                &case.id,
                bytes.as_bytes(),
                &format!("synthetic/{index}.json"),
            )
            .unwrap();
    }
    (root, store, engine, case.id)
}

fn corrupt_old_entry(store: &LocalStore, id: &CaseId) {
    let connection = store.db.lock().unwrap();
    connection
        .execute_batch("DROP TRIGGER audit_no_update")
        .unwrap();
    connection
        .execute(
            "UPDATE audit SET payload='altered' WHERE case_id=?1 AND seq=1",
            [id.as_str()],
        )
        .unwrap();
}

#[test]
fn reopening_a_case_rechecks_old_signed_entries() {
    let (_root, store, engine, id) = fixture();
    corrupt_old_entry(&store, &id);
    drop(engine);
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[61u8; 32]),
        actor: Actor::Analyst,
    });
    let reopened = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store,
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
    assert!(matches!(
        reopened.open_case_verified(&id, &CancellationToken::new()),
        Err(AppError::InvalidChain(_))
    ));
}

#[test]
fn explicit_verify_rechecks_old_entries_and_invalidates_the_checkpoint() {
    let (_root, store, engine, id) = fixture();
    corrupt_old_entry(&store, &id);
    assert!(matches!(engine.verify(&id), Err(AppError::InvalidChain(_))));
    assert!(matches!(
        engine.ingest(&id, br#"{"eventName":"Third"}"#, "synthetic/third.json"),
        Err(AppError::InvalidChain(_))
    ));
}
