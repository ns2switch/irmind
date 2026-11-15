use super::*;
use std::sync::atomic::AtomicBool;

struct WaitingQuery {
    entered: AtomicBool,
    exited: AtomicBool,
}
impl TaskEvidenceQueries for WaitingQuery {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        cancel: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        query.validate(view)?;
        self.entered.store(true, Ordering::SeqCst);
        let timeout = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !cancel.is_cancelled() && std::time::Instant::now() < timeout {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.exited.store(true, Ordering::SeqCst);
        assert!(
            cancel.is_cancelled(),
            "the synchronous query did not receive cancellation"
        );
        Err(AppError::Cancelled)
    }
}
#[test]
fn child_cancellation_reaches_a_synchronous_query_and_retains_it_until_joined() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let queries = Arc::new(WaitingQuery {
        entered: AtomicBool::new(false),
        exited: AtomicBool::new(false),
    });
    let (store, engine) =
        stored_history_engine_with_queries(root.path(), &history, &[], queries.clone());
    let started = start(&engine, &history);
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    let watch = queries.clone();
    let controller = std::thread::spawn(move || {
        let timeout = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !watch.entered.load(Ordering::SeqCst) && std::time::Instant::now() < timeout {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        signal.cancel();
    });
    let model = ToolModel {
        requests: std::sync::Mutex::new(vec![]),
        repeat: false,
        tool: Tool::GraphSummary,
    };
    let result = engine
        .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
        .unwrap();
    controller.join().unwrap();
    assert!(queries.entered.load(Ordering::SeqCst));
    assert!(queries.exited.load(Ordering::SeqCst));
    assert_eq!(result.status, SubagentStatus::Cancelled);
    assert_eq!(result.usage.calls, 1);
    assert_eq!(model.requests.lock().unwrap().len(), 1);
    engine.finish_subagent_plan(&started).unwrap();
    verify_and_export(store.as_ref(), &engine, &history, root.path());
}

struct LateQuery(Arc<irmind_testkit::FixedClock>);
impl TaskEvidenceQueries for LateQuery {
    fn execute(
        &self,
        _: &VerifiedTaskQueryView,
        _: TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        self.0.set(1000);
        Ok(TaskEvidenceResult::Text(
            "LATE_SYNTHETIC_RESULT_NOT_FOR_MODEL".into(),
        ))
    }
}
#[test]
fn late_child_queries_settle_the_call_but_do_not_accept_or_store_late_content() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(irmind_testkit::FixedClock::new(10));
    let queries = Arc::new(LateQuery(clock.clone()));
    let (store, mut engine) =
        stored_history_engine_with_queries(root.path(), &history, &[], queries);
    engine.clock = clock;
    let started = start(&engine, &history);
    let model = ToolModel {
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
    assert_eq!(result.status, SubagentStatus::Cancelled);
    assert_eq!(result.usage.calls, 1);
    assert_eq!(model.requests.lock().unwrap().len(), 1);
    engine.finish_subagent_plan(&started).unwrap();
    verify_and_export(store.as_ref(), &engine, &history, root.path());
    let export = std::fs::read(root.path().join("tool-child.irmind")).unwrap();
    assert!(
        !export
            .windows(b"LATE_SYNTHETIC_RESULT_NOT_FOR_MODEL".len())
            .any(|window| window == b"LATE_SYNTHETIC_RESULT_NOT_FOR_MODEL")
    );
}
