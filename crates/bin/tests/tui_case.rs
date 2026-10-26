#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CaseLock, CaseSeal, CompletionRequest, CryptoPorts,
    Engine, EnginePorts, EvidenceStore, LlmPort, ModelResponse, ModelStream, Repository, Signer,
    ThreatIntelPort, single_completion_stream,
};
#[cfg(feature = "keystore-file")]
use irmind_app::{KeystoreCapability, KeystoreManifest, SecretBackend, SignerBackend};
use irmind_domain::{
    Actor, AuthorizedCall, Case, CaseId, ExecutionMode, ProposedCall, Severity, Tool,
};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
#[cfg(feature = "keystore-file")]
use irmind_mod_keystore_file::FileKeystore;
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use irmind_tui::{
    WorkspaceIo,
    scripted::{ScriptedWorkspace, render_keystore_setup},
};
use ratatui::{Terminal, backend::TestBackend};
#[cfg(feature = "keystore-file")]
use secrecy::{ExposeSecret as _, SecretString};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

struct SlowRepository {
    store: Arc<LocalStore>,
    delay_next_read: AtomicBool,
}

impl Repository for SlowRepository {
    fn lock_case(&self, id: &CaseId) -> Result<Box<dyn CaseLock>, AppError> {
        self.store.lock_case(id)
    }
    fn get_case(&self, id: &CaseId) -> Result<Case, AppError> {
        if self.delay_next_read.swap(false, Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(3));
        }
        self.store.get_case(id)
    }
    fn list_cases(&self) -> Result<Vec<Case>, AppError> {
        self.store.list_cases()
    }
    fn write_seal_file(&self, id: &CaseId, seal: &CaseSeal) -> Result<(), AppError> {
        self.store.write_seal_file(id, seal)
    }
    fn case_seal(&self, id: &CaseId) -> Result<Option<CaseSeal>, AppError> {
        self.store.case_seal(id)
    }
}

struct TestSigner(SigningKey);

impl Signer for TestSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

struct FakeModel(AtomicUsize);

#[irmind_app::async_trait]
impl LlmPort for FakeModel {
    async fn complete(
        &self,
        _request: CompletionRequest,
        _cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        let first = self.0.fetch_add(1, Ordering::SeqCst) == 0;
        let calls = if first {
            vec![ProposedCall {
                tool: Tool::ThreatIntelExternal,
                args: BTreeMap::from([("ioc".into(), "example.com".into())]),
            }]
        } else {
            Vec::new()
        };
        Ok(single_completion_stream(
            ModelResponse {
                text: "Synthetic investigation".into(),
                raw: "synthetic".into(),
                calls,
            },
            None,
        ))
    }
}

struct FakeIntel;

#[irmind_app::async_trait]
impl ThreatIntelPort for FakeIntel {
    async fn execute(
        &self,
        call: &AuthorizedCall,
        _cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        assert_eq!(call.tool(), &Tool::ThreatIntelExternal);
        Ok(b"{\"verdict\":\"synthetic\"}".to_vec())
    }
}

struct TestIo(Arc<LocalStore>);

#[cfg(feature = "keystore-file")]
struct MigrationTarget(FileKeystore);

#[cfg(feature = "keystore-file")]
static MIGRATION_MANIFEST: KeystoreManifest = KeystoreManifest {
    id: "os",
    capabilities: &[KeystoreCapability::Signer, KeystoreCapability::Secrets],
    interactive_unlock: false,
    headless: true,
    network: false,
    config_fields: &[],
};

#[cfg(feature = "keystore-file")]
impl SignerBackend for MigrationTarget {
    fn manifest(&self) -> &'static KeystoreManifest {
        &MIGRATION_MANIFEST
    }
    fn load(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError> {
        self.0.load(actor)
    }
    fn create(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError> {
        self.0.create(actor)
    }
    fn public_key_for_actor(&self, actor: &Actor) -> Result<Vec<u8>, AppError> {
        self.0.public_key_for_actor(actor)
    }
    fn migration_recipient(&self, actor: &Actor) -> Result<[u8; 32], AppError> {
        self.0.migration_recipient(actor)
    }
    fn export_wrapped(&self, actor: &Actor, recipient: &[u8; 32]) -> Result<Vec<u8>, AppError> {
        self.0.export_wrapped(actor, recipient)
    }
    fn import_wrapped(&self, actor: Actor, packet: &[u8]) -> Result<(), AppError> {
        self.0.import_wrapped(actor, packet)
    }
}

#[cfg(feature = "keystore-file")]
impl SecretBackend for MigrationTarget {
    fn manifest(&self) -> &'static KeystoreManifest {
        &MIGRATION_MANIFEST
    }
    fn get(&self, name: &str) -> Result<SecretString, AppError> {
        self.0.get(name)
    }
    fn put(&self, name: &str, value: &SecretString) -> Result<(), AppError> {
        self.0.put(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), AppError> {
        self.0.delete(name)
    }
}

impl WorkspaceIo for TestIo {
    fn input_files(&self, root: &Path) -> anyhow::Result<Vec<PathBuf>> {
        Ok(vec![root.to_path_buf()])
    }
    fn read_evidence(&self, path: &Path) -> anyhow::Result<Vec<u8>> {
        Ok(std::fs::read(path)?)
    }
    fn audit_source_name(&self, _root: &Path, _file: &Path) -> anyhow::Result<String> {
        Ok("synthetic.json".into())
    }
    fn save_evidence(&self, path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
        Ok(std::fs::write(path, bytes)?)
    }
    fn verify_export(&self, path: &Path, expected_key: &str) -> anyhow::Result<String> {
        let (fingerprint, entries) = irmind_app::verify_export(
            &irmind_infra::LocalExportVerifier,
            path,
            Some(expected_key),
        )?;
        Ok(format!(
            "Verified {entries} entries; analyst key {fingerprint}"
        ))
    }
    fn case_exporter(&self) -> &dyn irmind_app::CaseExporter {
        self.0.as_ref()
    }
    fn keystore_status(&self) -> anyhow::Result<irmind_tui::KeystoreStatus> {
        Ok(irmind_tui::KeystoreStatus {
            signer_backend: "file".into(),
            secrets_backend: "file".into(),
            analyst_fingerprint: "synthetic".into(),
            credentials: Vec::new(),
            file_backend_active: true,
        })
    }
    fn put_credential(&self, _name: &str, _value: &secrecy::SecretString) -> anyhow::Result<()> {
        Ok(())
    }
    fn delete_credential(&self, _name: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn change_keystore_passphrase(&self, _value: &secrecy::SecretString) -> anyhow::Result<()> {
        Ok(())
    }
    fn migrate_keystore(
        &self,
        _engine: &Engine<'_>,
        _capability: &str,
        _target: &str,
        _passphrase: Option<&secrecy::SecretString>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

fn screen(terminal: &Terminal<TestBackend>) -> String {
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect::<String>()
}

#[cfg(feature = "keystore-file")]
#[test]
fn complete_case_without_os_keyring_from_tui_controller_with_fakes() {
    let root = tempfile::tempdir().unwrap();
    let mut setup_terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let choice = render_keystore_setup(&mut setup_terminal, false).unwrap();
    assert_eq!((choice.signer, choice.secrets), ("file", "file"));
    assert!(screen(&setup_terminal).contains("OS keyring: unavailable"));
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let file_backend = FileKeystore::open(
        root.path(),
        &SecretString::from("synthetic TUI passphrase".to_owned()),
        true,
    )
    .unwrap();
    let signer = file_backend.create(Actor::Analyst).unwrap();
    let intel = FakeIntel;
    let model = FakeModel(AtomicUsize::new(0));
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
    .unwrap()
    .with_threat_intel(&intel);
    let io_ops = TestIo(store.clone());
    let terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut tui = ScriptedWorkspace::new(terminal, &engine, Some(&model), &io_ops);

    tui.render_home().unwrap();
    assert!(screen(tui.terminal()).contains("IRMind"));
    tui.render_keystore().unwrap();
    assert!(screen(tui.terminal()).contains("Signer: file"));
    let id = tui.create_case("Synthetic incident", Severity::High,
        "v1;sources=siem-a;accounts=acct-a;hosts=;from=2026-10-23T10:00:00Z;to=2026-10-23T11:00:00Z").unwrap();
    tui.render_case(&id, "Case opened").unwrap();
    assert!(screen(tui.terminal()).contains("Synthetic incident"));

    let evidence = root.path().join("synthetic.json");
    std::fs::write(&evidence, br#"{"Records":[{"eventTime":"2026-10-23T10:10:00Z","eventName":"Login","sourceIPAddress":"203.0.113.9"}]}"#).unwrap();
    assert_eq!(tui.ingest_path(&id, &evidence).unwrap(), 1);
    tui.investigate(&id, "Investigate synthetic alert").unwrap();
    let pending = tui.pending_approval_ids(&id).unwrap();
    assert_eq!(pending.len(), 1);
    tui.approve(&id, &pending[0]).unwrap();
    let migration_home = tempfile::tempdir().unwrap();
    let migration_target = MigrationTarget(
        FileKeystore::open(
            migration_home.path(),
            &SecretString::from("second synthetic passphrase".to_owned()),
            true,
        )
        .unwrap(),
    );
    engine
        .migrate_signer_backend(&file_backend, &migration_target)
        .unwrap();
    assert_eq!(
        migration_target
            .public_key_for_actor(&Actor::Analyst)
            .unwrap(),
        signer.public_key()
    );
    file_backend
        .put(
            "SYNTHETIC_API_KEY",
            &SecretString::from("synthetic credential".to_owned()),
        )
        .unwrap();
    engine
        .migrate_secret_backend(&file_backend, &migration_target, &["SYNTHETIC_API_KEY"])
        .unwrap();
    assert_eq!(
        migration_target
            .get("SYNTHETIC_API_KEY")
            .unwrap()
            .expose_secret(),
        "synthetic credential"
    );
    assert!(
        store
            .global_operations()
            .unwrap()
            .iter()
            .any(|entry| entry.operation.contains("keystore-migration:signer"))
    );
    assert!(
        store
            .global_operations()
            .unwrap()
            .iter()
            .any(|entry| entry.operation.contains("keystore-migration:secrets"))
    );
    assert!(store.operations(&id).unwrap().is_empty());
    assert!(tui.verify(&id).unwrap() > 0);
    tui.seal(&id).unwrap();
    let export = root.path().join("synthetic.irmind.json");
    let fingerprint = tui.export(&id, &export).unwrap();
    assert_eq!(fingerprint.len(), 64);
    assert!(export.is_file());
    assert!(
        tui.verify_export(&export, &fingerprint)
            .unwrap()
            .contains("Verified")
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let cancelled_path = root.path().join("cancelled.irmind.json");
    assert!(matches!(
        irmind_app::export_case(&engine, store.as_ref(), &id, &cancelled_path, &cancelled),
        Err(AppError::Cancelled)
    ));
    assert!(!cancelled_path.exists());
    tui.render_case(&id, "Case sealed and exported").unwrap();
    tui.render_home().unwrap();
    assert!(screen(tui.terminal()).contains("sealed"));

    let hash = store.evidence_hashes(&id).unwrap().remove(0);
    std::fs::write(root.path().join("evidence").join(hash), b"tampered").unwrap();
    let rejected_export = root.path().join("must-not-export.irmind.json");
    assert!(tui.export(&id, &rejected_export).is_err());
    assert!(!rejected_export.exists());
}

#[cfg(feature = "keystore-file")]
#[test]
fn keystore_migration_without_a_case_is_globally_signed() {
    let root = tempfile::tempdir().unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let source = FileKeystore::open(
        root.path(),
        &SecretString::from("synthetic source passphrase".to_owned()),
        true,
    )
    .unwrap();
    let target = MigrationTarget(
        FileKeystore::open(
            target_root.path(),
            &SecretString::from("synthetic target passphrase".to_owned()),
            true,
        )
        .unwrap(),
    );
    let signer = source.create(Actor::Analyst).unwrap();
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
    source
        .put(
            "SYNTHETIC_API_KEY",
            &SecretString::from("fictional secret".to_owned()),
        )
        .unwrap();
    assert!(store.list_cases().unwrap().is_empty());
    engine.migrate_signer_backend(&source, &target).unwrap();
    engine
        .migrate_secret_backend(&source, &target, &["SYNTHETIC_API_KEY"])
        .unwrap();
    let operations = store.global_operations().unwrap();
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0].case_id, irmind_app::GLOBAL_OPERATION_SCOPE);
    assert_eq!(operations[1].prev, operations[0].hash);
    assert_eq!(
        target.public_key_for_actor(&Actor::Analyst).unwrap(),
        signer.public_key()
    );
    engine.verify_global_operations().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn tui_renders_while_a_local_port_is_slow() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let slow_repo = Arc::new(SlowRepository {
        store: store.clone(),
        delay_next_read: AtomicBool::new(false),
    });
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[120u8; 32])));
    let intel = FakeIntel;
    let model = FakeModel(AtomicUsize::new(0));
    let engine = Engine::new(
        EnginePorts::new(
            slow_repo.clone(),
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
    .unwrap()
    .with_threat_intel(&intel);
    let id = engine
        .create_case_with_severity("Synthetic slow port", Severity::Low, "local-only")
        .unwrap()
        .id;
    let io_ops = TestIo(store);
    let terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let mut tui = ScriptedWorkspace::new(terminal, &engine, Some(&model), &io_ops);
    slow_repo.delay_next_read.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let cancel = CancellationToken::new();
    let (investigation, tick) = tokio::join!(
        engine.investigate_cancelable(&id, "Synthetic alert", &model, &cancel),
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tui.render_home().unwrap();
            assert!(screen(tui.terminal()).contains("IRMind"));
            started.elapsed()
        }
    );
    assert!(investigation.is_ok());
    assert!(
        tick < Duration::from_secs(1),
        "TUI render tick was blocked by local I/O"
    );
}
