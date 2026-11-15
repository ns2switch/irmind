use super::*;
use irmind_app::subagents::SubagentStatus;

struct InterruptedModel;
#[async_trait]
impl LlmPort for InterruptedModel {
    async fn complete(
        &self,
        _: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        panic!("synthetic interruption after durable model dispatch");
    }
}

#[test]
fn interrupted_model_request_closes_without_replay_or_freeing_unreported_tokens() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, mut engine) = stored_history_engine(root.path(), &history, &[]);
    let started = tools::start(&engine, &history);
    let task = started.plan().tasks[0].task_id;
    let cancel = CancellationToken::new();
    let model = InterruptedModel;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.run_subagent_task(&started, task, &model, &cancel)
        }))
        .is_err()
    );
    assert!(engine.seal(&history.case).is_err());
    let before = store.entries(&history.case).unwrap();
    let request = before
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SubagentReservationV1)
        .map(|entry| {
            SubagentReservationV1::decode(
                &hex::decode(entry.payload.split_once(':').unwrap().1).unwrap(),
            )
            .unwrap()
        })
        .find(|request| request.purpose == ReservationPurpose::Model)
        .unwrap();
    // The organization may have changed since the interruption. Cancelling a
    // durable task does not need or confer permission to dispatch another call.
    engine.policy.denied_tools.push(Tool::GraphSummary);
    let result = engine.cancel_subagent_task(&started, task).unwrap();
    assert_eq!(result.status, SubagentStatus::Cancelled);
    assert_eq!(result.usage.tokens, request.amount.tokens);
    assert_eq!(result.usage.rounds, 1);
    assert_eq!(result.usage.calls, 0);
    assert_eq!(
        engine
            .cancel_subagent_task(&started, task)
            .unwrap()
            .canonical()
            .unwrap(),
        result.canonical().unwrap()
    );
    engine.finish_subagent_plan(&started).unwrap();
    let mut journal = SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
    for entry in store.entries(&history.case).unwrap() {
        journal.accept(&entry, &history.verifier).unwrap();
    }
    assert!(!journal.has_open_plans().unwrap());
    assert_eq!(journal.outstanding().unwrap().tokens, request.amount.tokens);
    tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}

#[test]
fn cancelling_an_unstarted_child_commits_a_zero_usage_result_without_provider_work() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let started = tools::start(&engine, &history);
    let result = engine
        .cancel_subagent_task(&started, started.plan().tasks[0].task_id)
        .unwrap();
    assert_eq!(result.usage, SubagentResources::default());
    assert_eq!(result.status, SubagentStatus::Cancelled);
    engine.finish_subagent_plan(&started).unwrap();
    tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}

struct FailToolSettlement {
    store: Arc<LocalStore>,
    failed: std::sync::atomic::AtomicBool,
}
impl irmind_app::AuditLog for FailToolSettlement {
    fn last_entry(&self, id: &CaseId) -> Result<Option<SignedEntry>, AppError> {
        self.store.last_entry(id)
    }
    fn transact(
        &self,
        entry: &SignedEntry,
        mutation: irmind_app::CaseMutation,
    ) -> Result<(), AppError> {
        self.store.transact(entry, mutation)
    }
    fn append_batch(&self, entries: &[SignedEntry]) -> Result<(), AppError> {
        let tool_settlement = entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SubagentReservationV1)
            .map(|entry| {
                SubagentReservationV1::decode(
                    &hex::decode(entry.payload.split_once(':').unwrap().1).unwrap(),
                )
                .unwrap()
            })
            .any(|request| {
                request.purpose == ReservationPurpose::Tool
                    && request.action == ReservationAction::SettleRequest
            });
        if tool_settlement && !self.failed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(AppError::Storage(
                "synthetic atomic append interruption".into(),
            ));
        }
        self.store.append_batch(entries)
    }
    fn entries(&self, id: &CaseId) -> Result<Vec<SignedEntry>, AppError> {
        self.store.entries(id)
    }
    fn last_operation(&self, id: &CaseId) -> Result<Option<irmind_app::SignedOperation>, AppError> {
        self.store.last_operation(id)
    }
    fn append_operation(&self, entry: &irmind_app::SignedOperation) -> Result<(), AppError> {
        self.store.append_operation(entry)
    }
    fn operations(&self, id: &CaseId) -> Result<Vec<irmind_app::SignedOperation>, AppError> {
        self.store.operations(id)
    }
    fn lock_global_operations(&self) -> Result<Box<dyn irmind_app::CaseLock>, AppError> {
        self.store.lock_global_operations()
    }
    fn global_operations(&self) -> Result<Vec<irmind_app::SignedOperation>, AppError> {
        self.store.global_operations()
    }
    fn append_global_operation(&self, entry: &irmind_app::SignedOperation) -> Result<(), AppError> {
        self.store.append_global_operation(entry)
    }
}

struct CountQueries(std::sync::atomic::AtomicUsize);
impl irmind_app::subagents::TaskEvidenceQueries for CountQueries {
    fn execute(
        &self,
        view: &irmind_app::subagents::VerifiedTaskQueryView,
        query: irmind_app::subagents::TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<irmind_app::subagents::TaskEvidenceResult, AppError> {
        query.validate(view)?;
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(irmind_app::subagents::TaskEvidenceResult::Text(
            "synthetic result".into(),
        ))
    }
}

#[test]
fn interrupted_tool_result_reconciles_its_existing_dispatch_once_without_repeating_the_effect() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let queries = Arc::new(CountQueries(std::sync::atomic::AtomicUsize::new(0)));
    let (store, mut engine) =
        stored_history_engine_with_queries(root.path(), &history, &[], queries.clone());
    let started = tools::start(&engine, &history);
    engine.audit_log = Arc::new(FailToolSettlement {
        store: store.clone(),
        failed: std::sync::atomic::AtomicBool::new(false),
    });
    let model = tools::ToolModel {
        requests: std::sync::Mutex::new(vec![]),
        repeat: false,
        tool: Tool::GraphSummary,
    };
    let result = engine
        .run_subagent_task(
            &started,
            started.plan().tasks[0].task_id,
            &model,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(result.status, SubagentStatus::Error);
    assert_eq!(result.usage.calls, 1);
    assert_eq!(result.usage.tokens, 7);
    assert_eq!(queries.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(model.requests.lock().unwrap().len(), 1);
    engine.finish_subagent_plan(&started).unwrap();
    tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}

#[test]
fn a_new_engine_closes_durable_preview_and_started_plans_without_an_execution_lease() {
    for admitted in [false, true] {
        let mut history = History::new();
        let root = tempfile::tempdir().unwrap();
        let (store, engine) = stored_history_engine(root.path(), &history, &[]);
        let prepared = engine
            .prepare_subagent_plan(
                &history.case,
                "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                vec![proposal(100_000)],
                SubagentResources::default(),
                &CancellationToken::new(),
            )
            .unwrap();
        if admitted {
            let started = engine
                .admit_subagent_plan(
                    &prepared,
                    &prepared.preview().automatic_start().unwrap(),
                    &CancellationToken::new(),
                )
                .unwrap()
                .unwrap();
            drop(started);
        }
        history.entries = store.entries(&history.case).unwrap();
        drop(prepared);
        drop(engine);
        let reopened = tempfile::tempdir().unwrap();
        let (store, engine) = stored_history_engine(reopened.path(), &history, &[]);
        assert_eq!(
            engine
                .cancel_interrupted_subagent_plans(&history.case)
                .unwrap(),
            1
        );
        assert_eq!(
            engine
                .cancel_interrupted_subagent_plans(&history.case)
                .unwrap(),
            0
        );
        tools::verify_and_export(store.as_ref(), &engine, &history, reopened.path());
    }
}

#[test]
fn restart_reconciliation_preserves_the_committed_prefix_and_unknown_provider_reservation() {
    use irmind_app::subagents::{
        BranchChunkRef, CheckedBranchChunk, SubagentBranchStore, SubagentCheckpointV1,
    };
    let mut history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let started = tools::start(&engine, &history);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.run_subagent_task(
                &started,
                started.plan().tasks[0].task_id,
                &InterruptedModel,
                &CancellationToken::new(),
            )
        }))
        .is_err()
    );
    history.entries = store.entries(&history.case).unwrap();
    let branches = ParquetStore::open(root.path()).unwrap();
    let chunks = history
        .entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SubagentCheckpointV1)
        .map(|entry| {
            let checkpoint = SubagentCheckpointV1::decode(
                &hex::decode(entry.payload.split_once(':').unwrap().1).unwrap(),
            )
            .unwrap();
            let reference =
                BranchChunkRef::new(checkpoint.chunk_sha256, checkpoint.chunk_bytes).unwrap();
            let bytes = branches
                .read(&history.case, &reference, &CancellationToken::new())
                .unwrap();
            CheckedBranchChunk::decode(
                bytes.as_bytes(),
                &history.agent.public_key(),
                &history.verifier,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    drop(started);
    drop(engine);
    let reopened = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(reopened.path(), &history, &chunks);
    assert_eq!(
        engine
            .cancel_interrupted_subagent_plans(&history.case)
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .cancel_interrupted_subagent_plans(&history.case)
            .unwrap(),
        0
    );
    let mut journal = SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
    for entry in store.entries(&history.case).unwrap() {
        journal.accept(&entry, &history.verifier).unwrap();
    }
    assert!(!journal.has_open_plans().unwrap());
    assert!(journal.outstanding().unwrap().tokens > 0);
    tools::verify_and_export(store.as_ref(), &engine, &history, reopened.path());
}
