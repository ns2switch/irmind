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
