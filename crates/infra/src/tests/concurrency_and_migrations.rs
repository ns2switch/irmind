use super::*;

#[test]
fn forged_approval_without_challenge_signature_fails_verification() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[61u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
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
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine.create_case("Approval", "local").unwrap();
    let model = ObedientModel {
        seen: Mutex::new(Vec::new()),
    };
    engine.investigate(&case.id, "Inspect", &model).unwrap();
    let id = engine.pending_approvals(&case.id).unwrap().remove(0).id;
    let last = store.last_entry(&case.id).unwrap().unwrap();
    let mut forged = SignedEntry {
        seq: last.seq + 1,
        case_id: case.id.as_str().into(),
        at: last.at,
        actor: Actor::Analyst,
        origin: "analyst".into(),
        kind: irmind_domain::AuditEventKind::ApprovalGranted,
        payload:
            serde_json::json!({"version":1,"id":id,"signature":"00","reason":null,"executed":false})
                .to_string(),
        evidence: None,
        prev: last.hash,
        hash: [0; 32],
        sig: Vec::new(),
        public_key: signer.public_key(),
    };
    forged.hash = sha256(&forged.canonical());
    forged.sig = signer.sign(&forged.hash).unwrap();
    store.append(&forged).unwrap();
    assert!(
        matches!(engine.verify(&case.id), Err(AppError::InvalidChain(seq)) if seq == forged.seq)
    );
}

#[test]
fn concurrent_ingest_serializes_a_case() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LocalStore>();
    assert_send_sync::<Engine<'_>>();
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[13u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
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
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine.create_case("Concurrent", "local").unwrap();
    std::thread::scope(|scope| {
        for number in 0..4 {
            let id = case.id.clone();
            let engine = &engine;
            let store = &store;
            scope.spawn(move || {
                let payload = format!("{{\"eventName\":\"Read\",\"host\":\"host-{number}\"}}");
                ingest_synthetic(
                    engine,
                    store.as_ref(),
                    &JsonParser,
                    &id,
                    payload.as_bytes(),
                    &format!("event-{number}.json"),
                );
            });
        }
    });
    assert_eq!(engine.verify(&case.id).unwrap(), 13);
}

#[test]
#[allow(clippy::too_many_lines)]
fn analyst_and_agent_entries_use_distinct_keys_in_one_export() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let analyst_key = SigningKey::from_bytes(&[21u8; 32]);
    let agent_key = SigningKey::from_bytes(&[22u8; 32]);
    let analyst = Arc::new(TestSigner {
        actor: Actor::Analyst,
        key: analyst_key,
    });
    let agent = Arc::new(TestSigner {
        actor: Actor::Agent(irmind_domain::AgentId::parse("watcher-1").unwrap()),
        key: agent_key,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let attended = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                analyst.clone(),
                Arc::new(
                    LocalVerifier::from_signer(analyst.as_ref())
                        .with_trusted_key(&agent.actor(), &agent.public_key())
                        .unwrap(),
                ),
            ),
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let unattended = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                agent.clone(),
                Arc::new(
                    LocalVerifier::from_signer(analyst.as_ref())
                        .with_trusted_key(&agent.actor(), &agent.public_key())
                        .unwrap(),
                ),
            ),
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Unattended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = attended.create_case("Alert", "local evidence").unwrap();
    assert!(matches!(
        ingest_synthetic_result(
            &unattended,
            store.as_ref(),
            parser.as_ref(),
            &case.id,
            b"{}",
            "log.json"
        ),
        Err(AppError::PendingApproval(_))
    ));
    unattended
        .investigate(&case.id, "Inspect local evidence", &QuietModel)
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| matches!(entry.actor, Actor::Agent(_)))
    );
    assert!(entries.iter().any(|entry| entry.actor == Actor::Analyst));
    attended.seal(&case.id).unwrap();
    let path = root.path().join("mixed.json");
    CaseExporter::export_case(store.as_ref(), &case.id, &path, &CancellationToken::new()).unwrap();
    assert!(verify_export(&path).is_ok());
}

#[test]
fn obsolete_graph_file_is_discarded_without_changing_the_signed_case() {
    let root = tempfile::tempdir().unwrap();
    let id = {
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[31u8; 32]),
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
        let id = engine.create_case("Migration", "local").unwrap().id;
        assert_eq!(engine.verify(&id).unwrap(), 1);
        id
    };
    let graph_dir = root.path().join("graph");
    std::fs::create_dir_all(&graph_dir).unwrap();
    let old_index = graph_dir.join(format!("{}.duckdb", id.as_str()));
    std::fs::write(&old_index, b"derived index").unwrap();
    let reopened = LocalStore::open(root.path()).unwrap();
    assert!(!old_index.exists());
    assert_eq!(reopened.entries(&id).unwrap().len(), 1);
    assert!(
        reopened
            .graph_summary(&id)
            .unwrap()
            .contains("Parquet records=0")
    );
}
