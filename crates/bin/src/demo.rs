//! An isolated, offline-first investigation using bundled synthetic telemetry.

use anyhow::{Result, anyhow, bail};
use irmind_app::{
    AppError, CancellationToken, CaseExporter, CaseId, CryptoPorts, Engine, EnginePorts, LlmPort,
    Severity, SignerBackend, ThreatIntelPort, hex,
    modules::{ModuleConfig, ModuleRegistry, ParserCatalog},
    sha256,
};
use irmind_domain::{Actor, AgentId, AuthorizedCall, ExecutionMode, Tool};
use irmind_infra::{LocalExportVerifier, LocalStore, LocalVerifier, SystemClock};
use irmind_mod_keystore_file::FileKeystore;
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use irmind_tui::{
    KeystoreStatus, ModuleKind, ModuleSelectionSource, ModuleStatus, WorkspaceIo, WorkspaceLaunch,
};
use secrecy::SecretString;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const EVENTS: &[u8] =
    include_bytes!("../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json");
static DEMO_VERIFICATION_PARSER: JsonParser = JsonParser;

fn demo_storage(root: &Path) -> Result<(Arc<LocalStore>, ParserCatalog), AppError> {
    let mut registry = ModuleRegistry::new();
    registry.register(Box::new(JsonParser), &ModuleConfig::new())?;
    registry.register(
        Box::new(
            irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new()
                .map_err(irmind_app::source_mapping::MappingError::into_app)?,
        ),
        &ModuleConfig::new(),
    )?;
    let parsers = registry
        .parser_catalog()
        .with_source_parser(irmind_mod_parser_json::source_log_parser())?;
    let store = LocalStore::open_mapped(root, Arc::new(registry.mapping_catalog()?))?;
    Ok((Arc::new(store), parsers))
}

mod model;
use model::ScriptedModel;

struct SyntheticIntel;

#[irmind_app::async_trait]
impl ThreatIntelPort for SyntheticIntel {
    async fn execute(
        &self,
        call: &AuthorizedCall,
        _cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::ThreatIntelExternal {
            return Err(AppError::Policy("unexpected demo tool".into()));
        }
        Ok(br#"{"source":"scripted demo","verdict":"synthetic"}"#.to_vec())
    }
}

struct DemoIo {
    store: Arc<LocalStore>,
    source: PathBuf,
    fingerprint: String,
    parser_catalog: ParserCatalog,
}

impl DemoIo {
    fn checked_source(&self, path: &Path) -> Result<()> {
        if path != self.source
            || std::fs::symlink_metadata(&self.source)?
                .file_type()
                .is_symlink()
        {
            bail!("demo accepts only the bundled synthetic episode");
        }
        Ok(())
    }
}

impl WorkspaceIo for DemoIo {
    fn demo_mode(&self) -> bool {
        true
    }
    fn demo_check(&self, engine: &Engine<'_>, id: &CaseId) -> Result<Option<String>> {
        let expected: serde_json::Value = serde_json::from_str(include_str!("demo/expected.json"))?;
        let confirmed = engine
            .findings(id)?
            .into_iter()
            .filter(|finding| finding.confirmed && !finding.dismissed)
            .collect::<Vec<_>>();
        let count = |field: &str| -> Result<(usize, usize)> {
            let items = expected
                .get(field)
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| anyhow!("invalid bundled demo answers"))?;
            let matches = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|item| confirmed.iter().any(|finding| finding.value.contains(item)))
                .count();
            Ok((matches, items.len()))
        };
        let events = count("malicious_event_ids")?;
        let entities = count("malicious_entity_ids")?;
        let techniques = count("expected_attack_techniques")?;
        Ok(Some(format!(
            "Local comparison with the bundled HuntEval answers: events {}/{}, entities {}/{}, ATT&CK techniques {}/{}. Only confirmed findings count. These answers were loaded for this check and were never sent to the model.",
            events.0, events.1, entities.0, entities.1, techniques.0, techniques.1
        )))
    }
    fn demo_export_identity(&self) -> Option<(PathBuf, String)> {
        Some((
            self.source.parent()?.join("demo-export.irmind.json"),
            self.fingerprint.clone(),
        ))
    }
    fn demo_source_root(&self) -> Option<PathBuf> {
        self.source.parent().map(Path::to_path_buf)
    }
    fn input_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        self.checked_source(root)?;
        Ok(vec![self.source.clone()])
    }
    fn parser_catalog(&self) -> Option<&ParserCatalog> {
        Some(&self.parser_catalog)
    }
    fn read_format_sample(&self, path: &Path) -> Result<Vec<u8>> {
        use std::io::Read as _;
        self.checked_source(path)?;
        let path = &self.source;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("selected source has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("selected source has no file name"))?;
        let file = irmind_fs::open_regular_no_follow(parent, Path::new(name))?;
        let mut sample = Vec::new();
        file.take(64 * 1024).read_to_end(&mut sample)?;
        Ok(sample)
    }
    fn read_evidence(&self, path: &Path) -> Result<Vec<u8>> {
        self.checked_source(path)?;
        Ok(std::fs::read(&self.source)?)
    }
    fn audit_source_name(&self, root: &Path, file: &Path) -> Result<String> {
        self.checked_source(root)?;
        self.checked_source(file)?;
        Ok("events.json".into())
    }
    fn save_evidence(&self, _path: &Path, _bytes: &[u8]) -> Result<()> {
        bail!("demo cannot save files outside its temporary directory")
    }
    fn verify_export(&self, path: &Path, expected_key: &str) -> Result<String> {
        let Some((allowed, fingerprint)) = self.demo_export_identity() else {
            bail!("demo export destination is unavailable");
        };
        if path != allowed || expected_key != fingerprint {
            bail!("demo verifies only its own temporary export and analyst key");
        }
        let (fingerprint, entries) =
            irmind_app::verify_export(&LocalExportVerifier, path, Some(expected_key))?;
        Ok(format!(
            "Verified {entries} entries; analyst key {fingerprint}"
        ))
    }
    fn case_exporter(&self) -> &dyn CaseExporter {
        self.store.as_ref()
    }
    fn large_case_exporter(&self) -> Option<&dyn irmind_app::LargeCaseExporter> {
        Some(self.store.as_ref())
    }
    fn large_case_store(&self) -> Option<&dyn irmind_app::LargeCaseStore> {
        Some(self.store.as_ref())
    }
    fn streaming_parser(&self) -> Option<&dyn irmind_app::StreamingEventParser> {
        // Verification requires the existing large-case use case's parser port.
        // Demo ingest still selects the parser through ParserCatalog.
        Some(&DEMO_VERIFICATION_PARSER)
    }
    fn keystore_status(&self) -> Result<KeystoreStatus> {
        Ok(KeystoreStatus {
            signer_backend: "ephemeral file".into(),
            secrets_backend: "ephemeral file".into(),
            analyst_fingerprint: self.fingerprint.clone(),
            credentials: Vec::new(),
            file_backend_active: true,
        })
    }
    fn put_credential(&self, _name: &str, _value: &SecretString) -> Result<()> {
        bail!("demo does not store credentials")
    }
    fn delete_credential(&self, _name: &str) -> Result<()> {
        bail!("demo has no credentials")
    }
    fn change_keystore_passphrase(&self, _value: &SecretString) -> Result<()> {
        bail!("demo keystore is deleted on exit")
    }
    fn migrate_keystore(
        &self,
        _engine: &Engine<'_>,
        _capability: &str,
        _target: &str,
        _passphrase: Option<&SecretString>,
    ) -> Result<()> {
        bail!("demo keystore cannot be migrated")
    }
    fn change_module_configuration(
        &self,
        _engine: &Engine<'_>,
        _change: irmind_app::ConfigChange,
        _confirmed: bool,
    ) -> Result<bool> {
        bail!("demo modules cannot be reconfigured")
    }
}

pub(super) fn run(
    shutdown: &CancellationToken,
    _scripted: bool,
    presentation_speed: u8,
) -> Result<()> {
    // Presentations never probe or select a network provider, including loopback.
    let selected: Option<String> = None;
    let model: Box<dyn LlmPort> = Box::new(ScriptedModel::with_speed(presentation_speed));
    let data = tempfile::tempdir()?;
    let outcome = run_in_directory(
        data.path(),
        model.as_ref(),
        selected.as_deref(),
        shutdown,
        presentation_speed,
    );
    data.close()?;
    outcome?;
    println!("Demo data deleted. To start a real case, run irmind and use /new and /settings.");
    Ok(())
}

fn run_in_directory(
    root: &Path,
    model: &dyn LlmPort,
    selected: Option<&str>,
    shutdown: &CancellationToken,
    presentation_speed: u8,
) -> Result<()> {
    let source = root.join("events.json");
    std::fs::write(&source, EVENTS)?;
    let (store, parser_catalog) = demo_storage(root)?;
    let keystore = FileKeystore::ephemeral(root)?;
    let signer = keystore.create(Actor::Analyst)?;
    let agent_id = AgentId::parse("demo-agent").map_err(|_| anyhow!("invalid demo agent ID"))?;
    let _agent = keystore.create(Actor::Agent(agent_id))?;
    let fingerprint = hex(&sha256(&signer.public_key()));
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
    );
    let intel = SyntheticIntel;
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock))?
        .with_threat_intel(&intel)
        .with_large_case_pipeline(store.clone(), irmind_mod_parser_json::source_log_parser())
        .with_parser_catalog(parser_catalog.clone());
    let case = engine.create_case_with_severity(
        "HuntEval · synthetic AWS IAM episode",
        Severity::Medium,
        "local evidence only",
    )?;
    let io = DemoIo {
        store,
        source,
        fingerprint,
        parser_catalog,
    };
    let modules = [ModuleStatus {
        id: selected
            .map_or("scripted-demo-model", |_| "ollama-local")
            .into(),
        compiled: true,
        enabled: true,
        configuration: "synthetic evidence, local model, deleted on exit".into(),
        kind: ModuleKind::Llm,
        selected: true,
        selection_source: ModuleSelectionSource::Persistent,
        parameters: Vec::new(),
        credentials: Vec::new(),
        missing: Vec::new(),
    }];
    let _ = irmind_tui::run_demo_presentation(
        &engine,
        Some(model),
        &io,
        &modules,
        shutdown,
        WorkspaceLaunch {
            initial_case: Some(&case.id),
            resume_last_case: irmind_tui::ResumeMode::Disabled,
            new_analyst_key: false,
            overrides_active: false,
            mouse_capture: false,
            theme: None,
            max_parallel_workers: None,
        },
        presentation_speed,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
