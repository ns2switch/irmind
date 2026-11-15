#![forbid(unsafe_code)]

//! Synthetic, offline TUI fixture used only by the versioned VHS tapes.

use anyhow::{Result, bail};
use futures_util::stream;
use irmind_app::{
    AppError, CancellationToken, CaseExporter, CaseId, CompletionRequest, CryptoPorts, Engine,
    EnginePorts, LlmPort, ModelEvent, ModelResponse, ModelStream, Severity, SignerBackend,
    ThreatIntelPort,
};
use irmind_domain::{Actor, AuthorizedCall, ExecutionMode, ProposedCall, Tool};
use irmind_infra::{LocalExportVerifier, LocalStore, LocalVerifier, SystemClock};
use irmind_mod_keystore_file::FileKeystore;
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
                    truncated: false,
                    text: text.into(),
                    raw: "synthetic-demo".into(),
                    calls: calls
                        .into_iter()
                        .enumerate()
                        .map(|(index, proposal)| {
                            irmind_app::ModelToolCall::from_proposal(
                                &format!("demo_call_{index}"),
                                proposal,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?,
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
    recent: Option<CaseId>,
    parsers: irmind_app::modules::ParserCatalog,
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

static VERIFICATION_PARSER: irmind_mod_parser_json::JsonParser = irmind_mod_parser_json::JsonParser;

impl WorkspaceIo for DemoIo {
    fn parser_catalog(&self) -> Option<&irmind_app::modules::ParserCatalog> {
        Some(&self.parsers)
    }
    fn read_format_sample(&self, path: &Path) -> Result<Vec<u8>> {
        use std::io::Read as _;
        checked_example(path)?;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(64 * 1024)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    fn large_case_store(&self) -> Option<&dyn irmind_app::LargeCaseStore> {
        Some(self.store.as_ref())
    }
    fn large_case_exporter(&self) -> Option<&dyn irmind_app::LargeCaseExporter> {
        Some(self.store.as_ref())
    }
    fn streaming_parser(&self) -> Option<&dyn irmind_app::StreamingEventParser> {
        Some(&VERIFICATION_PARSER)
    }
    fn load_last_case(&self) -> Result<Option<CaseId>> {
        Ok(self.recent.clone())
    }

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

fn demo_storage(root: &Path) -> Result<(Arc<LocalStore>, irmind_app::modules::ParserCatalog)> {
    use irmind_app::modules::{ModuleConfig, ModuleRegistry};
    let mut registry = ModuleRegistry::new();
    registry.register(
        Box::new(irmind_mod_parser_json::JsonParser),
        &ModuleConfig::new(),
    )?;
    registry.register(
        Box::new(irmind_mod_mapping_json_compat::JsonCompatibilityMapping::generic_only()?),
        &ModuleConfig::new(),
    )?;
    registry.register(
        Box::new(irmind_mod_mapping_cloudtrail::CloudTrailMapping::new()?),
        &ModuleConfig::new(),
    )?;
    let parsers = registry
        .parser_catalog()
        .with_source_parser(irmind_mod_parser_json::source_log_parser())?;
    let store = LocalStore::open_mapped(root, Arc::new(registry.mapping_catalog()?))?;
    Ok((Arc::new(store), parsers))
}

fn main() -> Result<()> {
    let resume = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("--resume") => true,
        Some(_) => bail!("the offline demo only supports --resume"),
    };
    let data = tempfile::tempdir()?;
    let (store, parsers) = demo_storage(data.path())?;
    let phrase = SecretString::from("offline synthetic demo phrase".to_owned());
    let keystore = FileKeystore::open(data.path(), &phrase, true)?;
    let signer = keystore.create(Actor::Analyst)?;
    let agent = keystore.create(Actor::Agent(
        irmind_domain::AgentId::parse("demo-agent")
            .map_err(|_| anyhow::anyhow!("invalid synthetic agent ID"))?,
    ))?;
    let ports = EnginePorts::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        CryptoPorts::new(
            signer.clone(),
            Arc::new(
                LocalVerifier::from_signer(signer.as_ref())
                    .with_trusted_key(&agent.actor(), &agent.public_key())?,
            ),
        ),
        Arc::new(MandatoryGuard::new()?),
    );
    let intel = DemoIntel;
    let model = DemoModel(AtomicUsize::new(0));
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock))?
        .with_threat_intel(&intel)
        .with_large_case_pipeline(store.clone(), irmind_mod_parser_json::source_log_parser())
        .with_parser_catalog(parsers.clone())
        .with_skills(irmind_app::SkillServices::new(
            Arc::new(irmind_infra::FileSkillPackageStore::new(data.path())),
            Arc::new(irmind_infra::TomlSkillCompiler),
            agent,
            irmind_infra::bundled_skill_candidates()?
                .into_iter()
                .map(|s| s.package().clone())
                .collect(),
        )?)?;
    let recent = if resume {
        Some(
            engine
                .create_case_with_severity(
                    "Recent synthetic case",
                    Severity::Medium,
                    "local evidence only",
                )?
                .id,
        )
    } else {
        None
    };
    let io = DemoIo {
        store,
        recent,
        parsers,
    };
    let modules = demo_modules();
    irmind_tui::run_workspace(
        &engine,
        Some(&model),
        &io,
        &modules,
        &CancellationToken::new(),
        WorkspaceLaunch {
            subagent_review: None,
            initial_case: None,
            resume_last_case: irmind_tui::ResumeMode::Enabled,
            new_analyst_key: false,
            overrides_active: false,
            mouse_capture: false,
            theme: None,
            max_parallel_workers: None,
        },
    )?;
    Ok(())
}

fn demo_modules() -> [ModuleStatus; 3] {
    [
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
                defaulted: false,
                required: true,
                overridden: false,
            }],
            credentials: vec!["OPENAI_API_KEY".into()],
            missing: vec!["model".into()],
        },
        ModuleStatus {
            id: "llm-deepseek".into(),
            compiled: true,
            enabled: false,
            configuration: "demo: not configured".into(),
            kind: ModuleKind::Llm,
            selected: false,
            selection_source: ModuleSelectionSource::Persistent,
            parameters: vec![ModuleParameter {
                name: "IRMIND_DEEPSEEK_BASE_URL".into(),
                value: "https://api.deepseek.com/".into(),
                defaulted: true,
                required: false,
                overridden: false,
            }],
            credentials: vec!["DEEPSEEK_API_KEY".into()],
            missing: vec!["DEEPSEEK_API_KEY".into()],
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
            missing: vec!["SPLUNK_TOKEN".into()],
        },
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn synthetic_original_verifies_after_mapped_preparation() -> anyhow::Result<()> {
        use irmind_app::LargeCaseStore as _;
        let directory = tempfile::tempdir()?;
        let (store, _) = super::demo_storage(directory.path())?;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        let paths = ["cloudtrail-alert.json".into()];
        let case = irmind_app::CaseId::parse("33333333-3333-3333-3333-333333333333")
            .map_err(|_| anyhow::anyhow!("invalid synthetic case"))?;
        let parser = irmind_mod_parser_json::source_log_parser();
        let cancel = irmind_app::CancellationToken::new();
        let prepared = store
            .prepare_mapped_ingest(
                irmind_app::MappedIngestRequest {
                    case_id: &case,
                    source_root: &root,
                    relative_paths: &paths,
                    copy_original: false,
                    parser: parser.as_ref(),
                    committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(&[]),
                    limits: irmind_app::PartitionLimits::default(),
                },
                &cancel,
            )?
            .ok_or_else(|| anyhow::anyhow!("no mapped preparation"))?;
        for source in &prepared.metadata().sources {
            store.verify_local_source(&root, &source.manifest, &cancel)?;
        }
        Ok(())
    }

    #[test]
    fn fixture_catalog_keeps_cloudtrail_and_generic_selectors_disjoint() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let (_store, _parsers) = super::demo_storage(directory.path())?;
        Ok(())
    }
}
