#![forbid(unsafe_code)]

//! Synthetic, offline TUI fixture used only by the versioned VHS tapes.

use anyhow::{Result, bail};
use futures_util::stream;
use irmind_app::{
    AppError, CancellationToken, CaseExporter, CompletionRequest, CryptoPorts, Engine, EnginePorts,
    LlmPort, ModelEvent, ModelResponse, ModelStream, SignerBackend, ThreatIntelPort,
};
use irmind_domain::{Actor, AuthorizedCall, ExecutionMode, ProposedCall, Tool};
use irmind_infra::{LocalExportVerifier, LocalStore, LocalVerifier, SystemClock};
use irmind_mod_keystore_file::FileKeystore;
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use irmind_tui::{
    KeystoreStatus, ModuleKind, ModuleParameter, ModuleSelectionSource, ModuleStatus, WorkspaceIo,
    WorkspaceLaunch,
};
use secrecy::SecretString;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const EXAMPLE: &str = "examples/cloudtrail-alert.json";

struct DemoModel(AtomicUsize);

#[irmind_app::async_trait]
impl LlmPort for DemoModel {
    fn descriptor(&self) -> String {
        "synthetic offline model".into()
    }

    async fn complete(
        &self,
        _request: CompletionRequest,
        _cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        let first = self.0.fetch_add(1, Ordering::SeqCst) == 0;
        let (text, calls) = if first {
            (
                "The synthetic record shows a role assumption. Review example.com before external enrichment.",
                vec![ProposedCall {
                    tool: Tool::ThreatIntelExternal,
                    args: BTreeMap::from([("ioc".into(), "example.com".into())]),
                }],
            )
        } else {
            (
                "The external lookup is waiting for the analyst's signed approval.",
                Vec::new(),
            )
        };
        let events = vec![
            ModelEvent::TextDelta(text[..text.len() / 2].into()),
            ModelEvent::TextDelta(text[text.len() / 2..].into()),
            ModelEvent::Completed {
                response: ModelResponse {
                    text: text.into(),
                    raw: "synthetic-demo".into(),
                    calls,
                },
                usage: None,
            },
        ];
        Ok(Box::pin(stream::iter(events.into_iter().map(|event| {
            std::thread::sleep(Duration::from_millis(350));
            Ok(event)
        }))))
    }
}

struct DemoIntel;

#[irmind_app::async_trait]
impl ThreatIntelPort for DemoIntel {
    async fn execute(
        &self,
        call: &AuthorizedCall,
        _cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::ThreatIntelExternal {
            return Err(AppError::Policy("unexpected demo tool".into()));
        }
        Ok(br#"{"verdict":"synthetic-only"}"#.to_vec())
    }
}

struct DemoIo {
    store: Arc<LocalStore>,
}

fn checked_example(path: &Path) -> Result<()> {
    if path != Path::new(EXAMPLE) {
        bail!("the offline demo accepts only its synthetic example")
    }
    for component in [Path::new("examples"), path] {
        if std::fs::symlink_metadata(component)?
            .file_type()
            .is_symlink()
        {
            bail!("the offline demo does not follow symbolic links")
        }
    }
    Ok(())
}

impl WorkspaceIo for DemoIo {
    fn input_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        checked_example(root)?;
        Ok(vec![root.to_path_buf()])
    }

    fn read_evidence(&self, path: &Path) -> Result<Vec<u8>> {
        checked_example(path)?;
        Ok(std::fs::read(path)?)
    }

    fn audit_source_name(&self, root: &Path, file: &Path) -> Result<String> {
        checked_example(root)?;
        checked_example(file)?;
        Ok("cloudtrail-alert.json".into())
    }

    fn save_evidence(&self, _path: &Path, _bytes: &[u8]) -> Result<()> {
        bail!("the offline demo does not write evidence outside its case")
    }

    fn verify_export(&self, path: &Path, expected_key: &str) -> Result<String> {
        let (fingerprint, count) =
            irmind_app::verify_export(&LocalExportVerifier, path, Some(expected_key))?;
        Ok(format!(
            "Verified {count} entries; analyst key {fingerprint}"
        ))
    }

    fn case_exporter(&self) -> &dyn CaseExporter {
        self.store.as_ref()
    }

    fn keystore_status(&self) -> Result<KeystoreStatus> {
        Ok(KeystoreStatus {
            signer_backend: "file".into(),
            secrets_backend: "file".into(),
            analyst_fingerprint: "ephemeral demo key".into(),
            credentials: Vec::new(),
            file_backend_active: true,
        })
    }

    fn put_credential(&self, _name: &str, _value: &SecretString) -> Result<()> {
        bail!("the offline demo does not store connector credentials")
    }

    fn delete_credential(&self, _name: &str) -> Result<()> {
        bail!("the offline demo has no connector credentials")
    }

    fn change_keystore_passphrase(&self, _value: &SecretString) -> Result<()> {
        bail!("the offline demo keeps its temporary keystore for one run")
    }

    fn migrate_keystore(
        &self,
        _engine: &Engine<'_>,
        _capability: &str,
        _target: &str,
        _passphrase: Option<&SecretString>,
    ) -> Result<()> {
        bail!("the offline demo cannot migrate its temporary key")
    }

    fn change_module_configuration(
        &self,
        _engine: &Engine<'_>,
        _change: irmind_app::ConfigChange,
        _confirmed: bool,
    ) -> Result<bool> {
        bail!("the offline demo has no configurable connector")
    }
}

fn main() -> Result<()> {
    let data = tempfile::tempdir()?;
    let store = Arc::new(LocalStore::open(data.path())?);
    let phrase = SecretString::from("offline synthetic demo phrase".to_owned());
    let keystore = FileKeystore::open(data.path(), &phrase, true)?;
    let signer = keystore.create(Actor::Analyst)?;
    let ports = EnginePorts::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        CryptoPorts::new(
            signer.clone(),
            Arc::new(LocalVerifier::from_signer(signer.as_ref())),
        ),
        Arc::new(MandatoryGuard::new()?),
        Arc::new(JsonParser),
    );
    let intel = DemoIntel;
    let model = DemoModel(AtomicUsize::new(0));
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock))?
        .with_threat_intel(&intel);
    let io = DemoIo { store };
    let modules = [
        ModuleStatus {
            id: "llm-openai-compatible".into(),
            compiled: true,
            enabled: false,
            configuration: "demo: not configured".into(),
            kind: ModuleKind::Llm,
            selected: false,
            selection_source: ModuleSelectionSource::Persistent,
            parameters: vec![ModuleParameter {
                name: "model".into(),
                value: String::new(),
                required: true,
                overridden: false,
            }],
            credentials: vec!["OPENAI_API_KEY".into()],
        },
        ModuleStatus {
            id: "siem-splunk".into(),
            compiled: true,
            enabled: false,
            configuration: "demo: not configured".into(),
            kind: ModuleKind::Connector,
            selected: false,
            selection_source: ModuleSelectionSource::Persistent,
            parameters: Vec::new(),
            credentials: vec!["SPLUNK_TOKEN".into()],
        },
    ];
    irmind_tui::run_workspace(
        &engine,
        Some(&model),
        &io,
        &modules,
        &CancellationToken::new(),
        WorkspaceLaunch {
            initial_case: None,
            new_analyst_key: false,
            overrides_active: false,
            mouse_capture: false,
        },
    )?;
    Ok(())
}
