//! An isolated, offline-first investigation using bundled synthetic telemetry.

use anyhow::{Result, anyhow, bail};
use futures_util::stream;
use irmind_app::{
    AppError, CancellationToken, CaseExporter, CaseId, CompletionRequest, CryptoPorts, Engine,
    EnginePorts, LlmPort, ModelEvent, ModelResponse, ModelStream, ModelToolCall, Severity,
    SignerBackend, ThreatIntelPort, hex, sha256,
};
use irmind_domain::{Actor, AgentId, AuthorizedCall, ExecutionMode, ProposedCall, Tool};
use irmind_infra::{LocalExportVerifier, LocalStore, LocalVerifier, SystemClock};
use irmind_mod_keystore_file::FileKeystore;
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use irmind_tui::{
    KeystoreStatus, ModuleKind, ModuleSelectionSource, ModuleStatus, WorkspaceIo, WorkspaceLaunch,
};
use secrecy::SecretString;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

const EVENTS: &[u8] = include_bytes!("../../parser-json/tests/fixtures/hunteval-aws-iam-001.json");
static PARSER: JsonParser = JsonParser;

struct ScriptedModel {
    round: AtomicUsize,
    source_hash: String,
}

impl ScriptedModel {
    fn new() -> Self {
        Self {
            round: AtomicUsize::new(0),
            source_hash: hex(&sha256(EVENTS)),
        }
    }
}

#[irmind_app::async_trait]
impl LlmPort for ScriptedModel {
    fn descriptor(&self) -> String {
        "scripted demo model · no network".into()
    }

    async fn complete(
        &self,
        _request: CompletionRequest,
        _cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        let round = self.round.fetch_add(1, Ordering::SeqCst);
        let (text, proposals) = match round {
            0 => ("I will inspect the signed synthetic events first.", vec![ProposedCall { tool: Tool::TextSearch, args: BTreeMap::from([("query".into(), "203.0.113.77".into()), ("limit".into(), "3".into())]) }]),
            1 => ("The synthetic events suggest privilege escalation and cross-account access. I am proposing a finding and an external lookup; the latter requires your signed approval.", vec![
                ProposedCall { tool: Tool::CaseAddFinding, args: BTreeMap::from([
                    ("kind".into(), "hypothesis".into()),
                    ("value".into(), "evt-0004 → evt-0005 → evt-0006: arn:aws:iam::111122223333:user/alex attached AdministratorAccess, assumed arn:aws:iam::444455556666:role/CrossAccountAdmin, then created an access key. Possible T1078 and T1098.".into()),
                    ("evidence_hash".into(), self.source_hash.clone()),
                    ("supporting_evidence".into(), self.source_hash.clone()),
                ]) },
                ProposedCall { tool: Tool::ThreatIntelExternal, args: BTreeMap::from([("ioc".into(), "203.0.113.77".into())]) },
            ]),
            _ => ("The evidence points to an administrative policy attachment, a cross-account role assumption, and an access-key creation. Confirm the proposed finding if supported, then use /demo check. All data in this session is synthetic.", Vec::new()),
        };
        let calls = proposals
            .into_iter()
            .enumerate()
            .map(|(index, proposal)| {
                ModelToolCall::from_proposal(&format!("demo_{round}_{index}"), proposal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let halfway = text.len() / 2;
        let split = text
            .char_indices()
            .map(|(index, _)| index)
            .rfind(|index| *index <= halfway)
            .unwrap_or(0);
        let response = ModelResponse {
            text: text.into(),
            calls,
            raw: "scripted-demo".into(),
            truncated: false,
        };
        let events = vec![
            Ok(ModelEvent::TextDelta(text[..split].into())),
            Ok(ModelEvent::TextDelta(text[split..].into())),
            Ok(ModelEvent::Completed {
                response,
                usage: None,
            }),
        ];
        Ok(Box::pin(stream::iter(events)))
    }
}

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
    ingest_pending: AtomicBool,
}

impl DemoIo {
    fn checked_source(&self, path: &Path) -> Result<()> {
        if path != self.source || std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            bail!("demo accepts only the bundled synthetic episode");
        }
        Ok(())
    }
}

impl WorkspaceIo for DemoIo {
    fn demo_mode(&self) -> bool {
        true
    }
    fn demo_initial_ingest(&self) -> Option<PathBuf> {
        self.ingest_pending
            .swap(false, Ordering::SeqCst)
            .then(|| self.source.clone())
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
    fn input_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        self.checked_source(root)?;
        Ok(vec![root.to_path_buf()])
    }
    fn read_evidence(&self, path: &Path) -> Result<Vec<u8>> {
        self.checked_source(path)?;
        Ok(std::fs::read(path)?)
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
        let (fingerprint, entries) =
            irmind_app::verify_export(&LocalExportVerifier, path, Some(expected_key))?;
        Ok(format!(
            "Verified {entries} entries; analyst key {fingerprint}"
        ))
    }
    fn case_exporter(&self) -> &dyn CaseExporter {
        self.store.as_ref()
    }
    fn large_case_store(&self) -> Option<&dyn irmind_app::LargeCaseStore> {
        Some(self.store.as_ref())
    }
    fn streaming_parser(&self) -> Option<&dyn irmind_app::StreamingEventParser> {
        Some(&PARSER)
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

pub(super) fn run(shutdown: &CancellationToken, scripted: bool) -> Result<()> {
    let available = if scripted {
        Vec::new()
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(
                irmind_mod_llm_openai_compatible::OpenAiCompatible::list_ollama_tool_models(
                    "http://127.0.0.1:11434/v1/",
                ),
            )
            .unwrap_or_default()
    };
    let selected = irmind_tui::choose_demo_model(&available, shutdown)?;
    if shutdown.is_cancelled() {
        return Ok(());
    }
    let model: Box<dyn LlmPort> = if let Some(name) = &selected {
        Box::new(irmind_mod_llm_openai_compatible::OpenAiCompatible::new(
            "http://127.0.0.1:11434/v1/",
            name,
            None,
        )?)
    } else {
        Box::new(ScriptedModel::new())
    };
    let data = tempfile::tempdir()?;
    let outcome = run_in_directory(data.path(), model.as_ref(), selected.as_deref(), shutdown);
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
) -> Result<()> {
    let source = root.join("events.json");
    std::fs::write(&source, EVENTS)?;
    let store = Arc::new(LocalStore::open(root)?);
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
        Arc::new(JsonParser),
    );
    let intel = SyntheticIntel;
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock))?
        .with_threat_intel(&intel)
        .with_large_case_pipeline(store.clone(), Arc::new(JsonParser));
    let case = engine.create_case_with_severity(
        "HuntEval · synthetic AWS IAM episode",
        Severity::Medium,
        "local evidence only",
    )?;
    let io = DemoIo {
        store,
        source,
        fingerprint,
        ingest_pending: AtomicBool::new(true),
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
    let _ = irmind_tui::run_workspace(
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
        },
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::LargeCaseUseCases;

    #[test]
    fn answer_check_is_local_and_does_not_call_the_model() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(temp.path()).unwrap());
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
            Arc::new(JsonParser),
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
            ingest_pending: AtomicBool::new(false),
        };
        let result = io.demo_check(&engine, &case.id).unwrap().unwrap();
        assert!(result.contains("events 0/3"));
        assert_eq!(model.round.load(Ordering::SeqCst), 0);
        assert!(!String::from_utf8_lossy(EVENTS).contains("expected_attack_techniques"));
    }

    #[test]
    fn scripted_investigation_proposes_a_signed_approval_and_checkable_finding() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("events.json"), EVENTS).unwrap();
        let store = Arc::new(LocalStore::open(temp.path()).unwrap());
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
            Arc::new(JsonParser),
        );
        let intel = SyntheticIntel;
        let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock))
            .unwrap()
            .with_threat_intel(&intel)
            .with_large_case_pipeline(store.clone(), Arc::new(JsonParser));
        let case = engine
            .create_case("Synthetic investigation", "local evidence only")
            .unwrap();
        let parser = JsonParser;
        LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &parser,
        }
        .ingest_local_batch(
            &case.id,
            temp.path(),
            &["events.json".into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
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
            ingest_pending: AtomicBool::new(false),
        };
        let result = io.demo_check(&engine, &case.id).unwrap().unwrap();
        assert!(result.contains("events 3/3"), "{result}");
        assert!(result.contains("entities 2/2"), "{result}");
        assert!(result.contains("ATT&CK techniques 2/2"), "{result}");
    }
}
