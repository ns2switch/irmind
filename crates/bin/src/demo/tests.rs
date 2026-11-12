#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{AuditLog as _, LargeCaseUseCases};

#[test]
fn answer_check_is_local_and_does_not_call_the_model() {
    let temp = tempfile::tempdir().unwrap();
    let (store, parser_catalog) = demo_storage(temp.path()).unwrap();
    let keystore = FileKeystore::ephemeral(temp.path()).unwrap();
    let signer = keystore.create(Actor::Analyst).unwrap();
    let ports = EnginePorts::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        CryptoPorts::new(
            signer.clone(),
            Arc::new(LocalVerifier::from_signer(signer.as_ref())),
        ),
        Arc::new(MandatoryGuard::new().unwrap()),
    );
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock)).unwrap();
    let case = engine
        .create_case("Synthetic check", "local evidence only")
        .unwrap();
    let model = ScriptedModel::new();
    let io = DemoIo {
        store,
        source: temp.path().join("events.json"),
        fingerprint: String::new(),
        parser_catalog,
    };
    let result = io.demo_check(&engine, &case.id).unwrap().unwrap();
    assert!(result.contains("events 0/3"));
    assert_eq!(model.requests(), 0);
    assert!(!String::from_utf8_lossy(EVENTS).contains("expected_attack_techniques"));
}

#[test]
fn scripted_investigation_proposes_a_signed_approval_and_checkable_finding() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("events.json"), EVENTS).unwrap();
    let (store, parser_catalog) = demo_storage(temp.path()).unwrap();
    let keystore = FileKeystore::ephemeral(temp.path()).unwrap();
    let signer = keystore.create(Actor::Analyst).unwrap();
    let ports = EnginePorts::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        CryptoPorts::new(
            signer.clone(),
            Arc::new(LocalVerifier::from_signer(signer.as_ref())),
        ),
        Arc::new(MandatoryGuard::new().unwrap()),
    );
    let intel = SyntheticIntel;
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock))
        .unwrap()
        .with_threat_intel(&intel)
        .with_large_case_pipeline(store.clone(), Arc::new(JsonParser));
    let case = engine
        .create_case("Synthetic investigation", "local evidence only")
        .unwrap();
    let parser = irmind_mod_parser_json::source_log_parser();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    }
    .ingest_local_batch(
        &case.id,
        temp.path(),
        &["events.json".into()],
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let entries = store.entries(&case.id).unwrap();
    let catalog = irmind_app::artifact_catalog(&entries).unwrap();
    assert!(!catalog.active.is_empty());
    assert!(
        catalog
            .active
            .iter()
            .all(|artifact| matches!(artifact, irmind_domain::ParquetArtifact::V3(_)))
    );
    let manifest = entries
        .iter()
        .find(|entry| entry.kind == irmind_domain::AuditEventKind::SourceManifestV2)
        .unwrap();
    assert_eq!(
        irmind_domain::SourceManifestV2::decode(&manifest.payload)
            .unwrap()
            .parser_version,
        "json-source-v1"
    );
    let model = ScriptedModel::new();
    engine
        .investigate(&case.id, "What happened?", &model)
        .unwrap();
    assert_eq!(engine.pending_approvals(&case.id).unwrap().len(), 1);
    let findings = engine.findings(&case.id).unwrap();
    assert_eq!(findings.len(), 1);
    engine.confirm_finding(&case.id, &findings[0].id).unwrap();
    let io = DemoIo {
        store,
        source: temp.path().join("events.json"),
        fingerprint: String::new(),
        parser_catalog,
    };
    let result = io.demo_check(&engine, &case.id).unwrap().unwrap();
    assert!(result.contains("events 3/3"), "{result}");
    assert!(result.contains("entities 2/2"), "{result}");
    assert!(result.contains("ATT&CK techniques 2/2"), "{result}");
}
