use super::*;

#[test]
fn local_errors_do_not_echo_external_values() {
    assert!(
        !storage("SECRET evidence path")
            .to_string()
            .contains("SECRET")
    );
    assert_eq!(
        storage_reason("evidence file exceeds 50 MB").to_string(),
        "storage: evidence file exceeds 50 MB"
    );
}
#[test]
fn refuses_oversized_evidence_file_before_loading_it() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("oversized");
    fs::File::create(&path)
        .unwrap()
        .set_len(50_000_001)
        .unwrap();
    assert!(read_evidence_file(&path).is_err());
}

pub(super) struct ObedientModel {
    pub(super) seen: Mutex<Vec<String>>,
}

pub(super) struct QuietModel;

pub(super) struct WaitingModel(std::sync::mpsc::Sender<()>);

#[async_trait]
impl LlmPort for WaitingModel {
    async fn complete(
        &self,
        _request: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        self.0
            .send(())
            .map_err(|error| AppError::Model(error.to_string()))?;
        cancel.cancelled().await;
        Err(AppError::Cancelled)
    }
}

#[test]
fn cancelling_model_request_is_audited_without_a_result() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[91u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
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
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine.create_case("Cancel", "test scope").unwrap();
    let (started, received) = std::sync::mpsc::channel();
    let model = WaitingModel(started);
    let cancel = CancellationToken::new();
    std::thread::scope(|scope| {
        let worker_cancel = cancel.clone();
        let engine_ref = &engine;
        let model_ref = &model;
        let case_id = &case.id;
        let worker = scope.spawn(move || {
            engine_ref.investigate_with_cancel(case_id, "investigate", model_ref, &worker_cancel)
        });
        received.recv().unwrap();
        cancel.cancel();
        assert!(matches!(worker.join().unwrap(), Err(AppError::Cancelled)));
    });
    let entries = store.entries(&case.id).unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::Cancelled)
    );
    assert!(!entries.iter().any(
        |entry| entry.kind == irmind_domain::AuditEventKind::ModelReply
            || entry.kind == irmind_domain::AuditEventKind::ToolResult
    ));
    assert_eq!(engine.verify(&case.id).unwrap(), entries.len());
}

pub(super) struct MissingReadModel;

streaming_test_model!(MissingReadModel);

impl LegacyModel for MissingReadModel {
    fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
        Ok(ModelResponse {
            text: String::new(),
            raw: "missing evidence read".into(),
            calls: vec![ProposedCall {
                tool: Tool::EvidenceRead,
                args: BTreeMap::from([("hash".into(), "a".repeat(64))]),
            }],
        })
    }
}

pub(super) struct RepeatingReadModel {
    pub(super) turns: Mutex<usize>,
}

pub(super) struct FindingModel {
    pub(super) hash: String,
    pub(super) turns: Mutex<usize>,
}

streaming_test_model!(FindingModel);

impl LegacyModel for FindingModel {
    fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
        let mut turns = self.turns.lock().map_err(storage)?;
        *turns += 1;
        Ok(if *turns == 1 {
            ModelResponse {
                text: String::new(),
                raw: "proposed finding".into(),
                calls: vec![ProposedCall {
                    tool: Tool::CaseAddFinding,
                    args: BTreeMap::from([
                        ("kind".into(), "ioc".into()),
                        ("value".into(), "198.51.100.9".into()),
                        ("evidence_hash".into(), self.hash.clone()),
                        ("ioc_type".into(), "ip".into()),
                        ("first_seen".into(), "2026-10-23T12:00:00Z".into()),
                        ("last_seen".into(), "2026-10-23T12:00:00Z".into()),
                        ("verdict".into(), "unknown".into()),
                    ]),
                }],
            }
        } else {
            ModelResponse {
                text: "done".into(),
                raw: "done".into(),
                calls: Vec::new(),
            }
        })
    }
}

pub(super) struct FakeExternalIntel {
    pub(super) calls: Mutex<usize>,
}

pub(super) struct WaitingIntel(std::sync::mpsc::Sender<()>);

#[irmind_app::async_trait]
impl ThreatIntelPort for WaitingIntel {
    async fn execute(
        &self,
        _call: &irmind_domain::AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        self.0
            .send(())
            .map_err(|error| AppError::Storage(error.to_string()))?;
        cancel.cancelled().await;
        Err(AppError::Cancelled)
    }
}

#[test]
fn cancelling_approved_external_call_is_audited_without_evidence() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[92u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let (started, received) = std::sync::mpsc::channel();
    let intel = WaitingIntel(started);
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
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_threat_intel(&intel);
    let case = engine
        .create_case("Approval cancellation", "local")
        .unwrap();
    let model = ObedientModel {
        seen: Mutex::new(Vec::new()),
    };
    engine.investigate(&case.id, "lookup", &model).unwrap();
    let request = engine.pending_approvals(&case.id).unwrap().remove(0);
    let cancel = CancellationToken::new();
    std::thread::scope(|scope| {
        let worker_cancel = cancel.clone();
        let engine_ref = &engine;
        let case_id = &case.id;
        let request_id = &request.id;
        let worker = scope
            .spawn(move || engine_ref.approve_with_cancel(case_id, request_id, &worker_cancel));
        received.recv().unwrap();
        cancel.cancel();
        assert!(matches!(worker.join().unwrap(), Err(AppError::Cancelled)));
    });
    let entries = store.entries(&case.id).unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::ApprovalGranted)
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::Cancelled)
    );
    assert!(
        !entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
    );
    assert_eq!(engine.verify(&case.id).unwrap(), entries.len());
}
