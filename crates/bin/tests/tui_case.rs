#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, CancellationToken, CaseLock, CaseSeal, CompletionRequest, CryptoPorts, Engine,
    EnginePorts, EvidenceStore, LlmPort, ModelResponse, ModelStream, Repository, Signer,
    ThreatIntelPort, single_completion_stream,
};
use irmind_domain::{
    Actor, AuthorizedCall, Case, CaseId, ExecutionMode, ProposedCall, Severity, Tool,
};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use irmind_tui::{WorkspaceIo, scripted::ScriptedWorkspace};
use ratatui::{Terminal, backend::TestBackend};
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

#[test]
fn complete_case_from_tui_controller_with_test_backend_and_fakes() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[119u8; 32])));
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
