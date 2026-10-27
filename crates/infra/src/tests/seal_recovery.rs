use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn seal_recovers_each_crash_boundary_and_refuses_inconsistent_chain() {
    for crash_point in ["intent", "temporary", "rename", "directory_sync"] {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[73u8; 32]),
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
        let case = engine.create_case("Crash test", "local scope").unwrap();
        engine.seal(&case.id).unwrap();
        let seal_path = root
            .path()
            .join("seals")
            .join(format!("{}.json", case.id.as_str()));
        let seal_bytes = fs::read(&seal_path).unwrap();
        store
            .conn()
            .unwrap()
            .execute(
                "UPDATE cases SET seal_pending=1 WHERE id=?1",
                [case.id.as_str()],
            )
            .unwrap();
        if matches!(crash_point, "intent" | "temporary") {
            fs::remove_file(&seal_path).unwrap();
        }
        let temporary = root
            .path()
            .join("seals")
            .join(format!(".{}.123.tmp", case.id.as_str()));
        if crash_point == "temporary" {
            fs::write(&temporary, &seal_bytes).unwrap();
        }
        drop(engine);
        drop(store);
        let recovered = LocalStore::open(root.path()).unwrap();
        assert!(
            recovered.case_seal(&case.id).unwrap().is_some(),
            "{crash_point}"
        );
        assert!(!temporary.exists(), "{crash_point}");
        let pending: i64 = recovered
            .conn()
            .unwrap()
            .query_row(
                "SELECT seal_pending FROM cases WHERE id=?1",
                [case.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "{crash_point}");
    }

    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[74u8; 32]),
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
    let case = engine.create_case("Inconsistent", "local scope").unwrap();
    engine.seal(&case.id).unwrap();
    fs::remove_file(
        root.path()
            .join("seals")
            .join(format!("{}.json", case.id.as_str())),
    )
    .unwrap();
    store
        .conn()
        .unwrap()
        .execute(
            "UPDATE cases SET title='tampered', seal_pending=1 WHERE id=?1",
            [case.id.as_str()],
        )
        .unwrap();
    drop(engine);
    drop(store);
    let recovered = Arc::new(LocalStore::open(root.path()).unwrap());
    assert!(matches!(
        recovered.case_seal(&case.id),
        Err(AppError::InvalidChain(0))
    ));
    let engine = Engine::new(
        EnginePorts::new(
            recovered.clone(),
            recovered.clone(),
            recovered.clone(),
            recovered.clone(),
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
    assert!(engine.verify(&case.id).is_err());
}

#[test]
fn crash_after_seal_transaction_without_seal_signature_is_inconsistent() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[75u8; 32]),
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
        .create_case("Crash before intent", "local scope")
        .unwrap();
    let last = store.last_entry(&case.id).unwrap().unwrap();
    let mut entry = SignedEntry {
        seq: last.seq + 1,
        case_id: case.id.as_str().into(),
        at: last.at + 1,
        actor: Actor::Analyst,
        origin: "analyst".into(),
        kind: irmind_domain::AuditEventKind::CaseSealed,
        payload: String::new(),
        evidence: None,
        prev: last.hash,
        hash: [0; 32],
        sig: Vec::new(),
        public_key: signer.public_key(),
    };
    entry.hash = sha256(&entry.canonical());
    entry.sig = signer.sign(&entry.hash).unwrap();
    store
        .transact(&entry, CaseMutation::Seal(case.id.clone()))
        .unwrap();
    drop(engine);
    drop(store);
    let reopened = LocalStore::open(root.path()).unwrap();
    assert!(matches!(
        reopened.case_seal(&case.id),
        Err(AppError::InvalidChain(0))
    ));
}
