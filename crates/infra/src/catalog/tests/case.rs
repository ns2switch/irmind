use super::*;
use crate::{LocalSigner, LocalStore, LocalVerifier, TomlSkillCompiler};
use irmind_app::{
    AuditLog, CancellationToken, CaseExporter, CryptoPorts, Engine, EnginePorts, SignedEntry,
    SignedOperation, Signer, SkillServices, SkillSnapshotV2,
    catalog::{BoundedPackageBytes, CatalogProofStore, CatalogReceipt},
};
use irmind_domain::{Actor, AgentId, AuditEventKind, Case, ExecutionMode};
use std::sync::Arc;

struct Fixture {
    root: tempfile::TempDir,
    store: Arc<LocalStore>,
    engine: Engine<'static>,
    case: Case,
    index: VerifiedCatalogIndex,
}
mod installation;
mod recovery;
fn fixture() -> Fixture {
    fixture_with_snapshot(true)
}
fn fixture_with_snapshot(pin: bool) -> Fixture {
    fixture_mode(pin, true)
}
fn fixture_mode(pin: bool, admit: bool) -> Fixture {
    fixture_keys(pin, admit, keys())
}
fn fixture_keys(pin: bool, admit: bool, release_keys: &'static [[u8; 32]]) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let mut store = LocalStore::open(root.path()).unwrap();
    store.catalog_verifier = Ed25519CatalogIndexVerifier::from_release_keys(release_keys).unwrap();
    let store = Arc::new(store);
    let analyst = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[42; 32]),
        actor: Actor::Analyst,
    });
    let engine = new_engine(
        root.path(),
        store.clone(),
        analyst.clone(),
        ExecutionMode::Attended,
    );
    let case = engine
        .create_case("Synthetic catalog custody", "local")
        .unwrap();
    let index = verified();
    let mut admission: SignedOperation = serde_json::from_slice(include_bytes!(
        "../../../../../docs/development/catalog-format-vectors/signed-installation.json"
    ))
    .unwrap();
    admission.public_key = analyst.public_key();
    admission.hash = irmind_app::sha256(&admission.canonical());
    admission.sig = analyst.sign(&admission.hash).unwrap();
    if admit {
        store.append_global_operation(&admission).unwrap();
        publish_package(root.path(), &index);
    }
    if pin {
        append_snapshot(&store, &case, &index, analyst.as_ref(), &admission);
    }
    Fixture {
        root,
        store,
        engine,
        case,
        index,
    }
}
fn new_engine(
    root: &std::path::Path,
    store: Arc<LocalStore>,
    analyst: Arc<dyn Signer>,
    mode: ExecutionMode,
) -> Engine<'static> {
    let agent = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[44; 32]),
        actor: Actor::Agent(AgentId::parse("skills-agent").unwrap()),
    });
    let verifier = Arc::new(
        LocalVerifier::from_signer(analyst.as_ref())
            .with_trusted_key(&agent.actor(), &agent.public_key())
            .unwrap(),
    );
    let services = SkillServices::new(
        Arc::new(crate::FileSkillPackageStore::new(root)),
        Arc::new(TomlSkillCompiler),
        agent,
        Vec::new(),
    )
    .unwrap()
    .with_catalog(
        store
            .catalog_services()
            .with_runtime_version("0.5.0")
            .unwrap(),
    );
    Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store,
            CryptoPorts::new(analyst, verifier),
            Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
        ),
        mode,
        Arc::new(crate::SystemClock),
    )
    .unwrap()
    .with_skills(services)
    .unwrap()
}
fn append_snapshot(
    store: &LocalStore,
    case: &Case,
    index: &VerifiedCatalogIndex,
    analyst: &LocalSigner,
    admission: &SignedOperation,
) {
    let receipt = CatalogReceipt::new(index, "synthetic-triage", true, false).unwrap();
    let bytes = BoundedPackageBytes::new(
        include_bytes!(
            "../../../../../docs/development/catalog-format-vectors/synthetic-triage-1.skill.json"
        )
        .to_vec(),
    )
    .unwrap();
    let skill = index
        .asset("synthetic-triage")
        .unwrap()
        .compile(&bytes, "0.5.0", &TomlSkillCompiler)
        .unwrap();
    let snapshot = SkillSnapshotV2::new_catalog(&skill, admission.hash, &receipt).unwrap();
    let last = store.last_entry(&case.id).unwrap().unwrap();
    let mut entry = SignedEntry {
        seq: last.seq + 1,
        case_id: case.id.as_str().into(),
        at: last.at,
        actor: Actor::Analyst,
        origin: "analyst".into(),
        kind: AuditEventKind::SkillSnapshotV2,
        payload: snapshot.encode().unwrap(),
        evidence: None,
        prev: last.hash,
        hash: [0; 32],
        sig: Vec::new(),
        public_key: analyst.public_key(),
    };
    entry.hash = irmind_app::sha256(&entry.canonical());
    entry.sig = analyst.sign(&entry.hash).unwrap();
    store.append(&entry).unwrap();
}
#[test]
fn catalog_case_verification_and_v8_export_require_the_independent_case_copy() {
    let f = fixture();
    let cancel = CancellationToken::new();
    f.store.publish(&f.index, &cancel).unwrap();
    assert!(f.engine.verify(&f.case.id).is_err());
    f.store
        .publish_for_case(&f.case.id, &f.index, &cancel)
        .unwrap();
    f.engine.verify(&f.case.id).unwrap();
    let proof = f
        .root
        .path()
        .join("parquet")
        .join(f.case.id.as_str())
        .join("catalog-proofs")
        .join(format!(
            "{}.proof",
            irmind_app::hex(f.index.proof_id().digest().as_bytes())
        ));
    let bytes = std::fs::read(&proof).unwrap();
    std::fs::write(&proof, b"changed").unwrap();
    assert!(f.engine.verify(&f.case.id).is_err());
    assert!(f.store.read(&f.index.proof_id(), &cancel).is_ok());
    std::fs::write(&proof, &bytes).unwrap();
    f.engine.seal(&f.case.id).unwrap();
    let path = f.root.path().join("synthetic.irmind");
    f.store.export_case(&f.case.id, &path, &cancel).unwrap();
    let verified =
        crate::seal::verify_export_with_catalog(&path, None, &f.store.catalog_verifier).unwrap();
    assert_eq!(verified.format_version, 9);
    assert!(crate::verify_export(&path).is_err()); // No production fixture key.
    std::fs::remove_file(&proof).unwrap();
    assert!(f.engine.verify(&f.case.id).is_err());
    let missing = f.root.path().join("missing.irmind");
    assert!(f.store.export_case(&f.case.id, &missing, &cancel).is_err());
    assert!(!missing.exists());
    assert!(f.store.read(&f.index.proof_id(), &cancel).is_ok());
    // The complete export verifies offline even after both local stores disappear.
    std::fs::remove_dir_all(f.root.path().join("catalog-proofs")).unwrap();
    crate::seal::verify_export_with_catalog(&path, None, &f.store.catalog_verifier).unwrap();
}

fn publish_package(root: &std::path::Path, index: &VerifiedCatalogIndex) {
    let bytes = BoundedPackageBytes::new(
        include_bytes!(
            "../../../../../docs/development/catalog-format-vectors/synthetic-triage-1.skill.json"
        )
        .to_vec(),
    )
    .unwrap();
    let skill = index
        .asset("synthetic-triage")
        .unwrap()
        .compile(&bytes, "0.5.0", &TomlSkillCompiler)
        .unwrap();
    irmind_app::SkillPackageStore::publish(
        &crate::FileSkillPackageStore::new(root),
        skill.metadata().name(),
        skill.package(),
    )
    .unwrap();
}

#[derive(Default)]
struct Model(std::sync::Mutex<Vec<irmind_app::CompletionRequest>>);
#[irmind_app::async_trait]
impl irmind_app::LlmPort for Model {
    async fn complete(
        &self,
        request: irmind_app::CompletionRequest,
        _: &CancellationToken,
    ) -> Result<irmind_app::ModelStream, AppError> {
        self.0.lock().unwrap().push(request);
        Ok(Box::pin(futures_util::stream::iter([Ok(
            irmind_app::ModelEvent::Completed {
                response: irmind_app::ModelResponse {
                    text: "Synthetic review complete.".into(),
                    calls: vec![],
                    raw: "synthetic".into(),
                    truncated: false,
                },
                usage: None,
            },
        )])))
    }
}
#[test]
fn catalog_first_load_pins_case_proof_before_exposure_and_never_repairs_missing_copy() {
    let f = fixture_with_snapshot(false);
    let cancel = CancellationToken::new();
    f.store.publish(&f.index, &cancel).unwrap();
    let model = Model::default();
    f.engine
        .investigate(&f.case.id, "/synthetic-triage", &model)
        .unwrap();
    let requests = model.0.lock().unwrap();
    assert!(requests.iter().flat_map(|r| &r.messages).any(|m| {
        m.content.contains("Review the signed synthetic events.") && m.content.contains("UNTRUSTED")
    }));
    assert!(
        requests
            .iter()
            .flat_map(|r| &r.messages)
            .filter(|m| m.role == irmind_app::MessageRole::System)
            .all(|m| !m.content.contains("Review the signed synthetic events."))
    );
    drop(requests);
    assert!(
        f.store
            .read_for_case(&f.case.id, &f.index.proof_id(), &cancel)
            .is_ok()
    );
    f.engine.verify(&f.case.id).unwrap();
    let proof = f
        .root
        .path()
        .join("parquet")
        .join(f.case.id.as_str())
        .join("catalog-proofs")
        .join(format!(
            "{}.proof",
            irmind_app::hex(f.index.proof_id().digest().as_bytes())
        ));
    std::fs::remove_file(&proof).unwrap();
    assert!(
        f.engine
            .investigate(&f.case.id, "/synthetic-triage", &model)
            .is_err()
    );
    assert!(!proof.exists());
    assert_eq!(model.0.lock().unwrap().len(), 1);
}
