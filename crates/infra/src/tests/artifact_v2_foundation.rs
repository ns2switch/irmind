use super::*;
use irmind_domain::AuditEventKind;

#[test]
fn known_v2_audit_event_cannot_be_silently_omitted_by_the_current_graph_reader() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
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
        payload: include_str!("../../../domain/tests/fixtures/parquet-artifact-v2.hex")
            .trim()
            .into(),
        evidence: None,
        prev: last.hash,
        hash: [0; 32],
        sig: Vec::new(),
        public_key: signer.public_key(),
    };
    entry.hash = sha256(&entry.canonical());
    entry.sig = signer.sign(&entry.hash).unwrap();
    store.append(&entry).unwrap();
    assert!(
        matches!(engine.verify(&case.id), Err(AppError::InvalidChain(seq)) if seq == entry.seq)
    );
    assert!(engine.prepare_seal(&case.id).is_err());
}

fn signed_export_with_inserted_kind(kind: AuditEventKind) -> serde_json::Value {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[32; 32]),
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
        .create_case("Unsupported artifact export", "local only")
        .unwrap();
    engine.seal(&case.id).unwrap();
    let mut entries = store.entries(&case.id).unwrap();
    let mut sealed = entries.pop().unwrap();
    let mut inserted = sealed.clone();
    inserted.kind = kind;
    inserted.payload = include_str!("../../../domain/tests/fixtures/parquet-artifact-v2.hex")
        .trim()
        .into();
    inserted.hash = sha256(&inserted.canonical());
    inserted.sig = signer.sign(&inserted.hash).unwrap();
    sealed.seq += 1;
    sealed.prev = inserted.hash;
    sealed.hash = sha256(&sealed.canonical());
    sealed.sig = signer.sign(&sealed.hash).unwrap();
    let mut seal = store.case_seal(&case.id).unwrap().unwrap();
    seal.seq = sealed.seq;
    seal.hash = sealed.hash;
    seal.sig = signer
        .sign(&seal_challenge(
            &case.id,
            sealed.seq,
            &sealed.hash,
            &sealed.payload,
        ))
        .unwrap();
    entries.extend([inserted, sealed]);
    serde_json::json!({"version":3,"case_id":case.id.as_str(),"title":case.title,
        "severity":case.severity.as_str(),"scope":case.scope,"audit":entries,"seal":seal,"evidence":{}})
}

fn v4_bytes(bundle: &serde_json::Value) -> Vec<u8> {
    let mut header = bundle.clone();
    let fields = header.as_object_mut().unwrap();
    fields.insert("version".into(), serde_json::json!(4));
    fields.remove("audit");
    fields.remove("evidence");
    let header = serde_json::to_vec(&header).unwrap();
    let mut bytes = b"IRMIND-EXPORT-V4\0".to_vec();
    bytes.extend_from_slice(&(header.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&header);
    let entries = bundle["audit"].as_array().unwrap();
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        let encoded = serde_json::to_vec(entry).unwrap();
        bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    // No evidence blobs, optional originals or operational entries.
    bytes.extend_from_slice(&[0; 24]);
    bytes
}

#[test]
fn v3_and_v4_reject_a_correctly_signed_premature_v2_instead_of_omitting_it() {
    let root = tempfile::tempdir().unwrap();
    for kind in [
        AuditEventKind::ModelReply,
        AuditEventKind::ParquetArtifactV2,
    ] {
        let bundle = signed_export_with_inserted_kind(kind);
        for bytes in [serde_json::to_vec(&bundle).unwrap(), v4_bytes(&bundle)] {
            let path = root.path().join("synthetic-export");
            fs::write(&path, bytes).unwrap();
            let result = verify_export(&path);
            if kind == AuditEventKind::ModelReply {
                assert!(
                    result.is_ok(),
                    "control has valid signatures, metadata and seal: {result:?}"
                );
            } else {
                assert!(matches!(result, Err(AppError::InvalidChain(2))));
            }
        }
    }
}
