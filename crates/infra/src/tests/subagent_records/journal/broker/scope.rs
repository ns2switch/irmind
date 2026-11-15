use super::*;
use irmind_app::subagents::{
    TaskEvidenceQueries, TaskEvidenceQuery, TaskEvidenceResult, VerifiedTaskQueryView,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct FrozenScope(AtomicUsize);
impl TaskEvidenceQueries for FrozenScope {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        query.validate(view)?;
        let expanded = irmind_domain::GraphQueryFilter::from_args(&BTreeMap::from([(
            "account".into(),
            "acct-b".into(),
        )]))
        .unwrap();
        assert!(
            !view.permits_filter(&expanded),
            "the task silently inherited the wider case scope"
        );
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(TaskEvidenceResult::Text(
            "The assigned source view did not expand.".into(),
        ))
    }
}
#[test]
fn changing_case_scope_does_not_expand_an_existing_task_or_invalidate_prior_receipts() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let queries = Arc::new(FrozenScope(AtomicUsize::new(0)));
    let (store, engine) =
        stored_history_engine_with_queries(root.path(), &history, &[], queries.clone());
    engine.change_scope(&history.case, "v1;sources=siem-a;accounts=acct-a;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-01T01:00:00Z").unwrap();
    let started = super::tools::start(&engine, &history);
    engine.change_scope(&history.case, "v1;sources=siem-a;accounts=acct-a,acct-b;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-01T01:00:00Z").unwrap();
    let model = super::tools::ToolModel {
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
    assert_eq!(
        result.status,
        irmind_app::subagents::SubagentStatus::Completed
    );
    assert_eq!(queries.0.load(Ordering::SeqCst), 1);
    engine.finish_subagent_plan(&started).unwrap();
    engine.change_scope(&history.case, "local").unwrap();
    super::tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}

#[test]
fn changed_organization_policy_prevents_dispatch_under_a_stale_task_plan() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, mut engine) = stored_history_engine(root.path(), &history, &[]);
    let started = super::tools::start(&engine, &history);
    engine.policy.denied_tools.push(Tool::GraphSummary);
    let model = child_model(true);
    let result = engine
        .run_subagent_task(
            &started,
            started.plan().tasks[0].task_id,
            &model,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(result.status, irmind_app::subagents::SubagentStatus::Error);
    assert!(model.requests.lock().unwrap().is_empty());
    let cancel = CancellationToken::new();
    cancel.cancel();
    engine
        .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
        .unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    super::tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}
