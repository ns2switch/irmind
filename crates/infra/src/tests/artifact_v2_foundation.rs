use super::*;
use irmind_domain::AuditEventKind;

#[test]
fn retired_artifact_kind_is_rejected_before_payload_interpretation() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(open_source_store(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[31; 32]),
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
        .create_case("V2 reader boundary", "local only")
        .unwrap();
    let last = store.last_entry(&case.id).unwrap().unwrap();
    let mut entry = SignedEntry {
        seq: last.seq + 1,
        case_id: case.id.as_str().into(),
        at: last.at,
        actor: Actor::Analyst,
        origin: "system".into(),
        kind: AuditEventKind::ParquetArtifactV2,
        payload: "unread-retired-payload".into(),
        evidence: None,
        prev: last.hash,
        hash: [0; 32],
        sig: Vec::new(),
        public_key: signer.public_key(),
    };
    entry.hash = sha256(&entry.canonical());
    entry.sig = signer.sign(&entry.hash).unwrap();
    store.append(&entry).unwrap();
    assert!(matches!(
        engine.verify(&case.id),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::RetiredCaseFormat
        ))
    ));
    assert!(engine.prepare_seal(&case.id).is_err());
}

#[test]
fn older_export_headers_fail_with_an_actionable_format_error() {
    let root = tempfile::tempdir().unwrap();
    for version in 3..=5 {
        let path = root.path().join(format!("synthetic-v{version}.irmind"));
        fs::write(&path, format!("IRMIND-EXPORT-V{version}\0")).unwrap();
        let error = verify_export(&path).unwrap_err();
        assert!(matches!(
            error,
            AppError::Fixed(irmind_app::FixedAppError::RetiredExportFormat)
        ));
        assert!(error.to_string().contains("verified originals"));
    }
}
