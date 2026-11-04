use super::*;
use irmind_app::{LargeCaseUseCases, ParserSelection};
use irmind_domain::{AuditEventKind, ParserSelectionMode};

#[test]
#[allow(clippy::too_many_lines)]
fn signed_mixed_case_verifies_rebuilds_and_rejects_parser_substitution() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("inputs");
    fs::create_dir(&sources).unwrap();
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
    let case = engine.create_case("Mixed precision", "local only").unwrap();
    let old = br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"Coarse"}"#;
    fs::write(sources.join("old.json"), old).unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    }
    .ingest_local(
        &case.id,
        &sources,
        "old.json",
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let precise = crate::ParquetStore::open_precise(root.path()).unwrap();
    let new = br#"{"eventTime":"2026-11-01T00:00:00.000001100Z","eventName":"Fine"}"#;
    fs::write(sources.join("new.json"), new).unwrap();
    let selections = BTreeMap::from([(
        "new.json".into(),
        ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-stream-v3".into(),
            confidence: 90,
            mode: ParserSelectionMode::Automatic,
            timestamp_context: None,
            format_sample_sha256: sha256(new),
        },
    )]);
    let uses = LargeCaseUseCases {
        engine: &engine,
        store: &precise,
        parser: &JsonParser,
    };
    uses.ingest_local_batch_selected(
        &case.id,
        &sources,
        &["new.json".into()],
        false,
        &selections,
        &CancellationToken::new(),
    )
    .unwrap();
    assert!(engine.verify(&case.id).is_ok());
    let timeline = store.timeline(&case.id, 10).unwrap();
    assert_eq!(timeline.len(), 2);
    assert_eq!(timeline[0].at, "2026-11-01T00:00:00.000001100Z");
    let checked = uses
        .verify_parquet_rebuild(&case.id, &sources, &CancellationToken::new())
        .unwrap();
    assert_eq!(checked, 2);
    let entries = store.entries(&case.id).unwrap();
    let mut original = entries
        .iter()
        .find(|e| e.kind == AuditEventKind::ParquetArtifactV2)
        .unwrap()
        .clone();
    let mut artifact = irmind_domain::ParquetArtifactV2::decode(&original.payload).unwrap();
    artifact.parser_id = "parser-ecs".into();
    let last = store.last_entry(&case.id).unwrap().unwrap();
    original.seq = last.seq + 1;
    original.prev = last.hash;
    original.payload = artifact.encode().unwrap();
    original.hash = sha256(&original.canonical());
    original.sig = signer.sign(&original.hash).unwrap();
    store.append(&original).unwrap();
    assert!(engine.verify(&case.id).is_err());
    assert!(store.timeline(&case.id, 10).is_err());
}
