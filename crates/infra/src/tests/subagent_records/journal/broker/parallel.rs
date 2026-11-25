use super::*;
use irmind_app::MessageRole;
use irmind_app::subagents::{
    StartedSubagentPlan, SubagentStatus, TaskEvidenceQueries, TaskEvidenceQuery,
    TaskEvidenceResult, VerifiedTaskQueryView,
};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};

struct Queries(AtomicUsize, bool);
impl TaskEvidenceQueries for Queries {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        query.validate(view)?;
        self.0.fetch_add(1, Ordering::SeqCst);
        let text = "Synthetic source-restricted summary.".into();
        Ok(if self.1 {
            TaskEvidenceResult::PartialText {
                text,
                reason: irmind_app::subagents::TaskQueryPartialReason::Sampling,
            }
        } else {
            TaskEvidenceResult::Text(text)
        })
    }
}

struct ParallelModel {
    rounds: std::sync::Mutex<BTreeMap<String, usize>>,
    live: AtomicUsize,
    peak: AtomicUsize,
}
impl ParallelModel {
    fn new() -> Self {
        Self {
            rounds: std::sync::Mutex::new(BTreeMap::new()),
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }
}
#[async_trait]
impl LlmPort for ParallelModel {
    fn output_profile(&self) -> irmind_app::ModelOutputProfile {
        irmind_app::ModelOutputProfile::known(2048, false).unwrap()
    }
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let nonce = request.messages[1]
            .content
            .split_once('>')
            .unwrap()
            .0
            .to_owned();
        let round = {
            let mut rounds = self.rounds.lock().unwrap();
            let count = rounds.entry(nonce).or_default();
            *count += 1;
            *count
        };
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(live, Ordering::SeqCst);
        let ready = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(std::sync::Mutex::new(None::<std::task::Waker>));
        let signal = ready.clone();
        let wake = waker.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(25));
            signal.store(true, Ordering::SeqCst);
            if let Some(waker) = wake.lock().unwrap().take() {
                waker.wake();
            }
        });
        futures_util::future::poll_fn(|context| {
            *waker.lock().unwrap() = Some(context.waker().clone());
            if ready.load(Ordering::SeqCst) {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        worker.join().unwrap();
        self.live.fetch_sub(1, Ordering::SeqCst);
        let calls = if round == 1 {
            vec![
                ModelToolCall::from_proposal(
                    "read_summary",
                    ProposedCall {
                        tool: Tool::GraphSummary,
                        args: BTreeMap::new(),
                    },
                )
                .unwrap(),
            ]
        } else {
            assert!(
                request
                    .messages
                    .iter()
                    .any(|message| message.role == MessageRole::Tool
                        && message.tool_call_id.as_deref() == Some("read_summary")
                        && message.content.contains("<UNTRUSTED_"))
            );
            vec![]
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic delegated review.".into(),
                calls,
                raw: "synthetic".into(),
                truncated: false,
            },
            Some(ModelUsage {
                cache: None,
                input_tokens: 5,
                output_tokens: 2,
            }),
        ))
    }
}

#[test]
fn parallel_child_models_overlap_but_signed_checkpoints_and_export_bytes_match_one_worker() {
    check_determinism(false);
    check_determinism(true);
}

fn check_determinism(partial: bool) {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            (0..4).map(|_| proposal(100_000)).collect(),
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let started = engine
        .admit_subagent_plan(
            &prepared,
            &prepared.preview().automatic_start().unwrap(),
            &cancel,
        )
        .unwrap()
        .unwrap();
    let prefix = store.entries(&history.case).unwrap();
    let mut expected = None;
    for workers in [1, 2, 4, 8] {
        let root = tempfile::tempdir().unwrap();
        let mut fork = History::new();
        fork.entries.clone_from(&prefix);
        let queries = Arc::new(Queries(AtomicUsize::new(0), partial));
        let (store, engine) =
            stored_history_engine_with_queries(root.path(), &fork, &[], queries.clone());
        let model = ParallelModel::new();
        let results = engine
            .run_subagent_plan(&started, &model, workers, &cancel)
            .unwrap();
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|result| result.status
            == if partial {
                SubagentStatus::Partial
            } else {
                SubagentStatus::Completed
            }
            && result.usage.calls == 1
            && result.usage.tokens == 14
            && result.usage.rounds == 2));
        assert_eq!(model.peak.load(Ordering::SeqCst), workers.min(4));
        assert_eq!(model.live.load(Ordering::SeqCst), 0);
        assert_eq!(queries.0.load(Ordering::SeqCst), 4);
        engine.finish_subagent_plan(&started).unwrap();
        tools::verify_and_export(store.as_ref(), &engine, &fork, root.path());
        let hashes = store
            .entries(&history.case)
            .unwrap()
            .into_iter()
            .map(|entry| entry.hash)
            .collect::<Vec<_>>();
        let export = std::fs::read(root.path().join("tool-child.irmind")).unwrap();
        match &expected {
            Some((prior_hashes, prior_export)) => {
                assert_eq!(&hashes, prior_hashes);
                assert_eq!(&export, prior_export);
            }
            None => expected = Some((hashes, export)),
        }
    }
}

#[derive(Debug)]
enum CancellationPhase {
    QueryEntered,
    CancellationObserved,
    PlanReturned(Option<Vec<SubagentStatus>>),
}

struct SelectiveQueries {
    target: SubagentDigest,
    phase: SyncSender<CancellationPhase>,
    allow_exit: Mutex<Receiver<()>>,
    exited: AtomicBool,
}
impl TaskEvidenceQueries for SelectiveQueries {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        cancel: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        query.validate(view)?;
        if view.task() == self.target {
            self.phase.send(CancellationPhase::QueryEntered).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cancel.is_cancelled() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(
                cancel.is_cancelled(),
                "the target query entered but did not observe cancellation"
            );
            self.phase
                .send(CancellationPhase::CancellationObserved)
                .unwrap();
            let exit = self
                .allow_exit
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5));
            assert!(
                exit.is_ok(),
                "the controller did not release the cancelled worker: {exit:?}"
            );
            self.exited.store(true, Ordering::SeqCst);
            return Err(AppError::Cancelled);
        }
        Ok(TaskEvidenceResult::Text(
            "Unaffected sibling result.".into(),
        ))
    }
}

fn cancel_entered_query(
    engine: &Engine<'_>,
    case: &CaseId,
    started: &StartedSubagentPlan,
    target: SubagentDigest,
    observed: &Receiver<CancellationPhase>,
    allow_exit: &SyncSender<()>,
) {
    // Start checking propagation only after the real blocking query
    // enters. Plan startup and journal verification can be scheduled late.
    match observed.recv().unwrap() {
        CancellationPhase::QueryEntered => {}
        CancellationPhase::PlanReturned(statuses) => {
            panic!("the plan returned before the target query entered: {statuses:?}")
        }
        CancellationPhase::CancellationObserved => {
            panic!("the query acknowledged cancellation before reporting its entry")
        }
    }
    assert!(engine.cancel_interrupted_subagent_plans(case).is_err());
    let other = CaseId::parse("00000000-0000-0000-0000-000000000088").unwrap();
    assert!(!engine.cancel_live_subagent_task(&other, target).unwrap());
    assert!(
        engine.cancel_live_subagent_task(case, target).unwrap(),
        "the target task lost its live handle after entering the query"
    );
    let next = observed
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| {
            panic!("no cancellation acknowledgement or terminal plan outcome: {error}")
        });
    assert!(
        matches!(next, CancellationPhase::CancellationObserved),
        "expected the query to observe cancellation, got {next:?}"
    );
    assert!(
        engine.finish_subagent_plan(started).is_err(),
        "the plan could release its allocation while the target query was still running"
    );
    allow_exit.send(()).unwrap();
}

#[test]
fn individual_live_cancellation_is_case_scoped_does_not_cancel_siblings_and_keeps_signed_results() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (_, first) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let prepared = first
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            (0..2).map(|_| proposal(100_000)).collect(),
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let started = first
        .admit_subagent_plan(
            &prepared,
            &prepared.preview().automatic_start().unwrap(),
            &cancel,
        )
        .unwrap()
        .unwrap();
    let target = started.plan().tasks[0].task_id;
    let (phase, observed) = mpsc::sync_channel(2);
    let (allow_exit, exit_allowed) = mpsc::sync_channel(1);
    let queries = Arc::new(SelectiveQueries {
        target,
        phase: phase.clone(),
        allow_exit: Mutex::new(exit_allowed),
        exited: AtomicBool::new(false),
    });
    // Reuse the same store through a fresh Engine so the signed prepared plan is retained.
    let mut fork = History::new();
    fork.entries = first.audit_log.entries(&history.case).unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let (store, engine) =
        stored_history_engine_with_queries(second_root.path(), &fork, &[], queries.clone());
    let model = ParallelModel::new();
    let results = std::thread::scope(|scope| {
        let engine = &engine;
        let started = &started;
        let case = &history.case;
        let controller = scope.spawn(move || {
            cancel_entered_query(engine, case, started, target, &observed, &allow_exit);
        });
        let result = engine.run_subagent_plan(started, &model, 2, &cancel);
        let statuses = result
            .as_ref()
            .ok()
            .map(|results| results.iter().map(|result| result.status).collect());
        let _ = phase.send(CancellationPhase::PlanReturned(statuses));
        controller.join().unwrap();
        assert!(
            queries.exited.load(Ordering::SeqCst),
            "the plan returned before the cancelled query exited"
        );
        result.unwrap()
    });
    assert_eq!(results[0].status, SubagentStatus::Cancelled);
    assert_eq!(results[1].status, SubagentStatus::Completed);
    assert_eq!(results[0].usage.calls, 1);
    assert_eq!(results[1].usage.calls, 1);
    assert!(!cancel.is_cancelled());
    assert!(
        !engine
            .cancel_live_subagent_task(&history.case, target)
            .unwrap()
    );
    assert_eq!(
        engine
            .cancel_live_subagent_plan(&history.case, started.plan().plan_id)
            .unwrap(),
        0
    );
    engine.finish_subagent_plan(&started).unwrap();
    tools::verify_and_export(store.as_ref(), &engine, &history, second_root.path());
}
