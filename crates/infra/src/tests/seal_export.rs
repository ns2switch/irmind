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
    let hash = ingest_synthetic(
        &engine,
        store.as_ref(),
        parser.as_ref(),
        &case.id,
        cloudtrail,
        "cloudtrail.json",
    );
    store.put_evidence(&case.id, &hash, cloudtrail).unwrap();
    assert_typed_report_entities(&engine, &case.id, &hash);
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
    assert!(
        store
            .entries(&case.id)
            .unwrap()
            .iter()
            .any(|entry| { entry.kind == irmind_domain::AuditEventKind::ParquetArtifactV1 })
    );
    assert!(
        store
            .graph_summary(&case.id)
            .unwrap()
            .contains("Parquet records=1")
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
    assert_eq!(
        irmind_app::verify_export_details(&LocalExportVerifier, &path, None)
            .unwrap()
            .format_version,
        4
    );
    let mut bundle = fs::read(&path).unwrap();
    let middle = bundle.len() / 2;
    bundle[middle] ^= 1;
    fs::write(&path, bundle).unwrap();
    assert!(verify_export(&path).is_err());
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

fn assert_typed_report_entities(engine: &Engine<'_>, id: &CaseId, hash: &str) {
    assert!(
        engine
            .add_entity(
                id,
                FindingKind::Timeline,
                "Missing record",
                hash,
                irmind_app::EntityDetails::Timeline {
                    at: "2026-10-23T12:00:00Z".into(),
                    source: "CloudTrail".into(),
                    record_index: Some(999)
                }
            )
            .is_err()
    );
    assert!(!engine.report(id).unwrap().contains("AssumeRole [evidence:"));
    let timeline_id = engine
        .add_entity(
            id,
            FindingKind::Timeline,
            "AssumeRole",
            hash,
            irmind_app::EntityDetails::Timeline {
                at: "2026-10-23T12:00:00Z".into(),
                source: "CloudTrail".into(),
                record_index: Some(0),
            },
        )
        .unwrap();
    assert!(!engine.report(id).unwrap().contains("AssumeRole [evidence:"));
    engine.confirm_finding(id, &timeline_id).unwrap();
    assert!(
        engine
            .report(id)
            .unwrap()
            .contains(&format!("AssumeRole [evidence: {hash}#0]"))
    );
    let hypothesis_id = engine
        .add_entity(
            id,
            FindingKind::Hypothesis,
            "Role abuse",
            hash,
            irmind_app::EntityDetails::Hypothesis {
                supporting_evidence: vec![hash.to_owned()],
                refuting_evidence: vec![],
            },
        )
        .unwrap();
    let technique_id = engine
        .add_entity(
            id,
            FindingKind::Technique,
            "T1078.004",
            hash,
            irmind_app::EntityDetails::Technique {
                technique_id: "T1078.004".into(),
            },
        )
        .unwrap();
    engine.confirm_finding(id, &hypothesis_id).unwrap();
    engine.confirm_finding(id, &technique_id).unwrap();
    let report = engine.report(id).unwrap();
    assert!(report.contains(&format!("Role abuse [supporting evidence: {hash}]")));
    assert!(report.contains(&format!("T1078.004 [evidence: {hash}]")));
}
