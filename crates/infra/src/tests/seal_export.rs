use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn sealed_export_verifies_without_local_key_and_detects_tampering() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[9u8; 32]),
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
    let case = engine
        .create_case("AWS alert", "account 123456789012")
        .unwrap();
    let cloudtrail = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole","sourceIPAddress":"203.0.113.8"}]}"#;
    let hash = engine
        .ingest(&case.id, cloudtrail, "cloudtrail.json")
        .unwrap();
    let finding_id = engine
        .add_finding(&case.id, FindingKind::Ioc, "203.0.113.8", &hash)
        .unwrap();
    assert!(!engine.report(&case.id).unwrap().contains("- 203.0.113.8"));
    engine.confirm_finding(&case.id, &finding_id).unwrap();
    assert!(engine.report(&case.id).unwrap().contains("- 203.0.113.8"));
    let discarded = engine
        .add_finding(&case.id, FindingKind::Hypothesis, "False hypothesis", &hash)
        .unwrap();
    engine
        .dismiss_finding(&case.id, &discarded, "not supported by the event")
        .unwrap();
    assert!(engine.confirm_finding(&case.id, &discarded).is_err());
    assert!(
        !engine
            .report(&case.id)
            .unwrap()
            .contains("False hypothesis")
    );
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::GraphIndexed
            && entry.payload.contains("graph=duckdb-graph-v3")
    }));
    assert!(
        store
            .graph_summary(&case.id)
            .unwrap()
            .contains("203.0.113.8")
    );
    let timeline = store.timeline(&case.id, 20).unwrap();
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].event, "AssumeRole");
    assert_eq!(timeline[0].evidence_hash, hash);
    engine.seal(&case.id).unwrap();
    let last = store.last_entry(&case.id).unwrap().unwrap();
    let seal = store.case_seal(&case.id).unwrap().unwrap();
    assert_ne!(seal.sig, last.sig);
    let path = root.path().join("export.json");
    let public_key =
        CaseExporter::export_case(store.as_ref(), &case.id, &path, &CancellationToken::new())
            .unwrap();
    assert_eq!(verify_export(&path).unwrap().0, public_key);
    assert_eq!(
        verify_export_expected(&path, Some(&public_key)).unwrap().0,
        public_key
    );
    assert!(matches!(
        verify_export_expected(&path, Some(&"0".repeat(64))),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::AdapterSignature(
                irmind_app::AdapterSignatureError::ExportKeyDoesNotMatchExpectedFingerprint
            )
        ))
    ));
    assert_eq!(
        store
            .case_seal(&case.id)
            .unwrap()
            .unwrap()
            .analyst_key_fingerprint,
        public_key
    );
    let mut bundle: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let original = bundle.clone();
    bundle["audit"][0]["kind"] = serde_json::json!("UnknownEvent");
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    assert!(verify_export(&path).is_err());
    bundle = original.clone();
    bundle["seal"]["sig"] = serde_json::json!(last.sig);
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    assert!(verify_export(&path).is_err());
    bundle = original;
    bundle["evidence"][&hash] = serde_json::Value::String(BASE64.encode(b"tampered"));
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    assert!(matches!(
        verify_export(&path),
        Err(AppError::EvidenceMismatch(_))
    ));
}

#[test]
fn oversized_export_is_rejected_before_parsing() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("oversized.json");
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_EXPORT_BYTES as u64 + 1).unwrap();
    assert!(verify_export(&path).is_err());
}

#[test]
#[allow(clippy::panic)]
fn approval_signature_cannot_be_reused_as_audit_signature() {
    let signer = LocalSigner {
        key: SigningKey::from_bytes(&[82u8; 32]),
        actor: Actor::Analyst,
    };
    let case = Case {
        id: CaseId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
        title: "Replay".into(),
        severity: Severity::Medium,
        scope: "local scope".into(),
        sealed: false,
    };
    let irmind_domain::Decision::NeedsApproval(pending) = irmind_domain::evaluate(
        &case,
        ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "example.com".into())]),
        },
        4,
        ExecutionMode::Attended,
        1_700_000_000,
    ) else {
        panic!("expected pending approval")
    };
    let signature = signer.sign(&pending.challenge()).unwrap();
    assert!(verify_signature(&signer.public_key(), &pending.challenge(), &signature).is_ok());
    let audit_hash = sha256(b"irmind-audit-v2\0different-entry");
    assert!(verify_signature(&signer.public_key(), &audit_hash, &signature).is_err());
}

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
