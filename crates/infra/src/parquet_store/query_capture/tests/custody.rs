use super::*;
use crate::{
    AuditLog, CaseMutation, FileSkillPackageStore, LocalSigner, LocalStore, LocalVerifier, Signer,
    TomlSkillCompiler,
};
use ed25519_dalek::SigningKey;
use irmind_app::source_queries::{
    SignedSourceQueryAdmission, SourceQueryReservationV1, query_content_id,
};
use irmind_app::{
    CryptoPorts, Engine, EnginePorts, LargeCaseExporter, SignedEntry, SignedOperation,
};
use irmind_domain::{
    Actor, AgentId, AuditEventKind, Case, CaseScope, ExecutionMode, PolicyRules, Severity,
};
use irmind_security::MandatoryGuard;

const CONFIGURATION: &[u8] = include_bytes!(
    "../../../../../../docs/development/source-query-format-vectors/signed-configuration.json"
);
const CHAIN: &[u8] = include_bytes!(
    "../../../../../../docs/development/source-query-format-vectors/signed-record-chain.json"
);
const IDS: &[u8] = include_bytes!(
    "../../../../../../docs/development/source-query-format-vectors/identities.json"
);

#[test]
fn engine_query_capture_survives_reopen_reconstruction_seal_and_v9_export() {
    let root = tempfile::tempdir().unwrap();
    let decoder = TestDecoder.identity();
    let (catalog, template) = synthetic_catalog_and_result(decoder);
    let analyst = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[77; 32]),
        actor: Actor::Analyst,
    });
    let agent = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[88; 32]),
        actor: Actor::Agent(AgentId::parse("main").unwrap()),
    });
    let (chain, capture) = remap_vector(&template, agent.as_ref(), analyst.as_ref());
    let case = case();
    let store = Arc::new(LocalStore::open_mapped(root.path(), catalog.clone()).unwrap());
    record_query_prefix(store.as_ref(), &case, &chain);
    let decoder = Arc::new(
        catalog
            .decoder_selection(decoder.name, decoder.version)
            .unwrap(),
    );
    let engine = engine(root.path(), store.clone(), decoder.clone(), analyst, agent);
    let cancel = CancellationToken::new();
    let mut spool = reserve_and_stage(&engine, &case, &chain, &cancel);
    spool.write_all(&capture).unwrap();
    let hash = engine
        .publish_source_query_capture(
            &case,
            &chain[7].payload,
            &chain[8].payload,
            &spool,
            decoder.as_ref(),
            &cancel,
        )
        .unwrap();
    drop(spool);
    assert_eq!(hash, EvidenceHash::from_bytes(irmind_app::sha256(&capture)));
    assert!(engine.open_case_verified(&case, &cancel).is_ok());
    assert_eq!(
        irmind_app::LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: decoder.as_ref(),
        }
        .verify_parquet_rebuild(&case, root.path(), &cancel)
        .unwrap(),
        1
    );
    engine.seal(&case).unwrap();
    check_v9_export(root.path(), store.as_ref(), &case, &cancel);
}

fn engine(
    root: &Path,
    store: Arc<LocalStore>,
    decoder: Arc<dyn irmind_app::StreamingEventParser>,
    analyst: Arc<LocalSigner>,
    agent: Arc<LocalSigner>,
) -> Engine<'static> {
    let verifier = LocalVerifier::from_signer(analyst.as_ref())
        .with_trusted_key(&agent.actor(), &agent.public_key())
        .unwrap();
    Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(analyst, Arc::new(verifier)),
            Arc::new(MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(irmind_testkit::FixedClock::new(1_794_960_000)),
    )
    .unwrap()
    .with_policy(PolicyRules {
        scope: Some(CaseScope::parse("v1;sources=aws-lab;accounts=111122223333;hosts=;from=2026-11-01T00:00:00Z;to=2026-12-01T00:00:00Z").unwrap()),
        ..PolicyRules::default()
    }, "a".repeat(64)).unwrap()
    .with_large_case_pipeline(store, decoder)
    .with_skills(
        irmind_app::SkillServices::new(
            Arc::new(FileSkillPackageStore::new(root)),
            Arc::new(TomlSkillCompiler),
            agent,
            vec![],
        )
        .unwrap(),
    )
    .unwrap()
}

fn reserve_and_stage(
    engine: &Engine<'_>,
    case: &CaseId,
    chain: &[SignedEntry],
    cancel: &CancellationToken,
) -> tempfile::NamedTempFile {
    let reservation = SourceQueryReservationV1::decode(chain[4].payload.as_bytes())
        .unwrap()
        .content_id()
        .unwrap();
    assert!(
        engine
            .prepare_source_query_capture_spools(case, &reservation, cancel)
            .is_err()
    );
    let configuration: SignedOperation = serde_json::from_slice(CONFIGURATION).unwrap();
    let admission = SignedSourceQueryAdmission {
        plan: &chain[2],
        approval: Some(&chain[3]),
        reservation: &chain[4],
        intent: &chain[5],
        configuration: &configuration,
    };
    engine
        .persist_source_query_reservation(case, admission, false, cancel)
        .unwrap();
    assert!(
        engine
            .persist_source_query_reservation(case, admission, false, cancel)
            .is_err()
    );
    engine
        .persist_source_query_observation(case, &chain[6], cancel)
        .unwrap();
    let (writer, output) = engine
        .prepare_source_query_capture_spools(case, &reservation, cancel)
        .unwrap();
    drop(writer);
    output
}

fn check_v9_export(root: &Path, store: &LocalStore, case: &CaseId, cancel: &CancellationToken) {
    for include_originals in [false, true] {
        let export = root.join(format!("query-{include_originals}.irmind"));
        let fingerprint =
            LargeCaseExporter::export_case(store, case, &export, None, include_originals, cancel)
                .unwrap();
        let (verified, _) = crate::verify_export_expected(&export, Some(&fingerprint)).unwrap();
        assert_eq!(verified, fingerprint);
        let mut changed = fs::read(&export).unwrap();
        *changed.last_mut().unwrap() ^= 1;
        fs::write(&export, changed).unwrap();
        assert!(crate::verify_export_expected(&export, Some(&fingerprint)).is_err());
    }
}

fn record_query_prefix(store: &LocalStore, case: &CaseId, chain: &[SignedEntry]) {
    let configuration: SignedOperation = serde_json::from_slice(CONFIGURATION).unwrap();
    store.append_global_operation(&configuration).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&chain[0].payload).unwrap();
    store
        .transact(
            &chain[0],
            CaseMutation::Create(Case {
                id: case.clone(),
                title: meta["title"].as_str().unwrap().into(),
                severity: Severity::Medium,
                scope: meta["scope"].as_str().unwrap().into(),
                sealed: false,
            }),
        )
        .unwrap();
    store.append_batch(&chain[1..4]).unwrap();
}

/// Use the approved wire vectors with a deterministic synthetic mapper whose
/// implementation digest is known to the test. Provider page bytes stay exact.
fn remap_vector(
    template: &SourceQueryResultV1,
    agent: &dyn Signer,
    analyst: &dyn Signer,
) -> (Vec<SignedEntry>, Vec<u8>) {
    let mut chain: Vec<SignedEntry> = serde_json::from_slice(CHAIN).unwrap();
    let ids: BTreeMap<String, String> = serde_json::from_slice(IDS).unwrap();
    let template_json = serde_json::to_value(template).unwrap();
    let mut replacements: Vec<(&str, String)> = vec![(
        "a799cf54941b7079db5e92f8c94431a4607e70890796d12fbfd4092402b33383",
        template_json["mapping"]["sha256"].as_str().unwrap().into(),
    )];
    let mut captured = capture();
    let mut prior = chain[1].hash;
    let sequence = [
        "plan",
        "approval",
        "reservation",
        "intent",
        "execution",
        "result",
        "settlement",
    ];
    for (entry, name) in chain.iter_mut().skip(2).zip(sequence) {
        for (before, after) in &replacements {
            entry.payload = entry.payload.replace(before, after);
        }
        let value: serde_json::Value = serde_json::from_str(&entry.payload).unwrap();
        let kind = if name == "intent" { "execution" } else { name };
        let identity = query_content_id(&format!("irmind-source-query-{kind}-v1"), &value).unwrap();
        replacements.push((ids[name].as_str(), identity.clone()));
        if name == "plan" {
            let old = ids[name].as_bytes();
            let offset = captured
                .windows(old.len())
                .position(|part| part == old)
                .unwrap();
            captured[offset..offset + old.len()].copy_from_slice(identity.as_bytes());
            replacements.push((
                ids["capture_sha256"].as_str(),
                irmind_app::hex(&irmind_app::sha256(&captured)),
            ));
        }
        entry.prev = prior;
        let signer = if entry.kind == AuditEventKind::SourceQueryApprovalV1 {
            analyst
        } else {
            agent
        };
        entry.hash = irmind_app::sha256(&entry.canonical());
        entry.sig = signer.sign(&entry.hash).unwrap();
        prior = entry.hash;
    }
    (chain, captured)
}
