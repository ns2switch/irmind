use super::*;
use irmind_app::subagents::{EngineEvent, EngineEventKind, EngineEventSubscription, EventCursor};

struct EventQueries {
    calls: std::sync::atomic::AtomicUsize,
}
impl irmind_app::subagents::TaskEvidenceQueries for EventQueries {
    fn execute(
        &self,
        view: &irmind_app::subagents::VerifiedTaskQueryView,
        query: irmind_app::subagents::TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<irmind_app::subagents::TaskEvidenceResult, AppError> {
        query.validate(view)?;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(irmind_app::subagents::TaskEvidenceResult::Text(
            "Synthetic read-only projection.".into(),
        ))
    }
}

fn drain(
    subscription: &mut dyn EngineEventSubscription,
    cursor: &mut EventCursor,
    max: u16,
) -> Vec<EngineEvent> {
    let mut events = Vec::new();
    for _ in 0..1024 {
        let batch = subscription
            .poll(*cursor, max, &CancellationToken::new())
            .unwrap();
        assert!(batch.events.len() <= usize::from(max));
        assert!(
            batch
                .events
                .iter()
                .map(|event| event.payload.len() + 512)
                .sum::<usize>()
                <= 1024 * 1024
        );
        assert!(
            batch
                .events
                .iter()
                .all(|event| event.payload.len() <= 16 * 1024)
        );
        assert!(batch.next.position() >= cursor.position());
        *cursor = batch.next;
        events.extend(batch.events);
        if !batch.more {
            return events;
        }
    }
    panic!("event replay did not terminate");
}

#[test]
fn task_approval_replay_is_attributed_guarded_and_does_not_resolve_or_dispatch() {
    let mut history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let started = tools::start(&engine, &history);
    let request =
        super::pending::publish_pending(store.as_ref(), root.path(), &mut history, &started);
    let before = store.entries(&history.case).unwrap();
    let (mut cursor, mut subscription) = engine.subscribe_case_events(&history.case).unwrap();
    let events = drain(subscription.as_mut(), &mut cursor, 1);
    let approvals = events
        .iter()
        .filter(|event| event.kind == EngineEventKind::Approval)
        .collect::<Vec<_>>();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].task_id, Some(started.plan().tasks[0].task_id));
    assert_eq!(approvals[0].task_type.as_deref(), Some("triage"));
    assert!(approvals[0].payload.contains(&request));
    assert!(approvals[0].payload.contains("ti_lookup_external"));
    assert!(
        approvals[0]
            .payload
            .contains(&engine.guard.screen("203.0.113.77").unwrap().text)
    );
    assert_eq!(engine.pending_approvals(&history.case).unwrap().len(), 1);
    assert_eq!(
        store
            .entries(&history.case)
            .unwrap()
            .iter()
            .map(|entry| entry.hash)
            .collect::<Vec<_>>(),
        before.iter().map(|entry| entry.hash).collect::<Vec<_>>()
    );
}

#[test]
fn event_poll_is_read_only_bounded_cursor_based_and_reconnect_replays_without_effects() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let queries = Arc::new(EventQueries {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let (store, engine) =
        stored_history_engine_with_queries(root.path(), &history, &[], queries.clone());
    let started = tools::start(&engine, &history);
    let (mut cursor, mut subscription) = engine.subscribe_case_events(&history.case).unwrap();
    let preview = drain(subscription.as_mut(), &mut cursor, 1);
    assert!(
        preview
            .iter()
            .any(|event| event.kind == EngineEventKind::PlanPreview)
    );
    let model = tools::ToolModel {
        requests: std::sync::Mutex::new(vec![]),
        repeat: false,
        tool: Tool::GraphSummary,
    };
    engine
        .run_subagent_task(
            &started,
            started.plan().tasks[0].task_id,
            &model,
            &CancellationToken::new(),
        )
        .unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    let before = store
        .entries(&history.case)
        .unwrap()
        .iter()
        .map(|entry| entry.hash)
        .collect::<Vec<_>>();
    let events = drain(subscription.as_mut(), &mut cursor, 1);
    assert!(
        events
            .windows(2)
            .all(|pair| pair[0].cursor.position() < pair[1].cursor.position())
    );
    for kind in [
        EngineEventKind::Round,
        EngineEventKind::Message,
        EngineEventKind::ToolProposal,
        EngineEventKind::ToolResult,
        EngineEventKind::Status,
        EngineEventKind::Budget,
        EngineEventKind::Checkpoint,
    ] {
        assert!(
            events.iter().any(|event| event.kind == kind),
            "missing {kind:?}"
        );
    }
    assert!(
        events
            .iter()
            .all(|event| event.version == 1 && event.case_id == history.case)
    );
    let (mut reconnect, mut replay) = engine.subscribe_case_events(&history.case).unwrap();
    let repeated = drain(replay.as_mut(), &mut reconnect, 1024);
    assert_eq!(repeated.len(), preview.len() + events.len());
    assert_eq!(queries.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(model.requests.lock().unwrap().len(), 2);
    assert_eq!(
        store
            .entries(&history.case)
            .unwrap()
            .iter()
            .map(|entry| entry.hash)
            .collect::<Vec<_>>(),
        before
    );
    assert_invalid_cursors(subscription.as_mut(), cursor, store.as_ref(), &history);
}

fn assert_invalid_cursors(
    subscription: &mut dyn EngineEventSubscription,
    cursor: EventCursor,
    store: &LocalStore,
    history: &History,
) {
    assert!(
        subscription
            .poll(cursor, 0, &CancellationToken::new())
            .is_err()
    );
    assert!(
        subscription
            .poll(cursor, 1025, &CancellationToken::new())
            .is_err()
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        subscription.poll(cursor, 1, &cancelled),
        Err(AppError::Cancelled)
    ));
    // A new engine session cannot resume another session's opaque cursor.
    let mut fork = History::new();
    fork.entries = store.entries(&history.case).unwrap();
    let other_root = tempfile::tempdir().unwrap();
    let (_, other) = stored_history_engine(other_root.path(), &fork, &[]);
    let (_, mut foreign) = other.subscribe_case_events(&history.case).unwrap();
    assert!(foreign.poll(cursor, 1, &CancellationToken::new()).is_err());
}

#[test]
fn event_cache_reauthenticates_changed_prior_bytes_even_when_tip_hash_is_unchanged() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let _started = tools::start(&engine, &history);
    let (initial, mut subscription) = engine.subscribe_case_events(&history.case).unwrap();
    let batch = subscription
        .poll(initial, 1024, &CancellationToken::new())
        .unwrap();
    assert!(!batch.events.is_empty());
    let prior_tip = store.entries(&history.case).unwrap().last().unwrap().hash;
    {
        let db = store.db.lock().unwrap();
        db.execute_batch("DROP TRIGGER audit_no_update").unwrap();
        db.execute(
            "UPDATE audit SET payload='altered' WHERE case_id=?1 AND seq=1",
            [history.case.as_str()],
        )
        .unwrap();
    }
    assert_eq!(
        store.entries(&history.case).unwrap().last().unwrap().hash,
        prior_tip
    );
    assert!(
        subscription
            .poll(initial, 1024, &CancellationToken::new())
            .is_err()
    );
}

#[test]
fn plan_mailbox_waits_for_the_actual_analyst_and_dropped_reviews_do_not_forge_consent() {
    use irmind_app::subagents::{AnalystPlanInteraction, AnalystPlanMailbox};
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(500_001)],
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let mailbox = AnalystPlanMailbox::default();
    let choice = std::thread::scope(|scope| {
        let waiting = scope.spawn(|| block_on_review(mailbox.review(prepared.preview(), &cancel)));
        let request = wait_for_review(&mailbox, &history.case);
        assert!(request.preview().confirmation_required());
        assert!(request.preview().automatic_start().is_err());
        assert!(
            !store
                .entries(&history.case)
                .unwrap()
                .iter()
                .any(|entry| entry.kind == AuditEventKind::SubagentPlanApprovalV1)
        );
        request.start().unwrap();
        waiting.join().unwrap().unwrap()
    });
    assert!(choice.explicit() && choice.starts());
    let started = engine
        .admit_subagent_plan(&prepared, &choice, &cancel)
        .unwrap()
        .unwrap();
    for task in &started.plan().tasks {
        engine.cancel_subagent_task(&started, task.task_id).unwrap();
    }
    engine.finish_subagent_plan(&started).unwrap();
    let before = store.entries(&history.case).unwrap().len();
    std::thread::scope(|scope| {
        let waiting = scope.spawn(|| block_on_review(mailbox.review(prepared.preview(), &cancel)));
        drop(wait_for_review(&mailbox, &history.case));
        assert!(waiting.join().unwrap().is_err());
    });
    assert_eq!(store.entries(&history.case).unwrap().len(), before);
}
fn wait_for_review(
    mailbox: &irmind_app::subagents::AnalystPlanMailbox,
    case: &CaseId,
) -> irmind_app::subagents::PlanReview {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Some(request) = mailbox.take_review(case).unwrap() {
            return request;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("Analyst review did not arrive");
}

fn block_on_review(
    mut future: irmind_app::subagents::PortFuture<'_, irmind_app::subagents::AnalystPlanChoice>,
) -> Result<irmind_app::subagents::AnalystPlanChoice, AppError> {
    struct ThreadWake(std::thread::Thread);
    impl std::task::Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let std::task::Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "review future did not complete"
        );
        std::thread::park_timeout(std::time::Duration::from_millis(10));
    }
}

#[test]
fn plan_preview_names_only_its_frozen_signed_sources_before_start() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let own = super::findings::source(
        root.path(),
        store.as_ref(),
        &engine,
        &history.case,
        "assigned.json",
        br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"ConsoleLogin"}"#,
    );
    super::findings::source(
        root.path(),
        store.as_ref(),
        &engine,
        &history.case,
        "unassigned.json",
        br#"{"eventTime":"2026-11-01T01:00:00Z","eventName":"GetRole"}"#,
    );
    let mut task = proposal(100_000);
    task.sources = vec![own.clone()];
    task.objective = "The model cannot rename signed sources".into();
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![task],
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let preview = prepared.preview();
    let summary = preview
        .source_summary(preview.tasks()[0].source_set_sha256)
        .unwrap();
    assert!(
        summary.contains("Sources (1)")
            && summary.contains("assigned.json")
            && summary.contains(&own.as_str()[..8])
    );
    assert!(!summary.contains("unassigned.json"));
    engine
        .admit_subagent_plan(&prepared, &preview.cancel().unwrap(), &cancel)
        .unwrap();
    engine.verify(&history.case).unwrap();
}
