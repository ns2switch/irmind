mod cancellation;
mod partial;
use super::*;
use irmind_app::subagents::{
    SubagentStatus, TaskEvidenceQueries, TaskEvidenceQuery, TaskEvidenceResult,
    VerifiedTaskQueryView,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Queries(AtomicUsize);
impl TaskEvidenceQueries for Queries {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        query.validate(view)?;
        assert!(view.sources().is_empty());
        assert!(view.generation_seq() > 0);
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(TaskEvidenceResult::Text(
            "Synthetic restricted summary: 0 records.".into(),
        ))
    }
}
pub(super) struct ToolModel {
    pub(super) requests: std::sync::Mutex<Vec<CompletionRequest>>,
    pub(super) repeat: bool,
    pub(super) tool: Tool,
}
#[async_trait]
impl LlmPort for ToolModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let mut requests = self.requests.lock().unwrap();
        let number = requests.len() + 1;
        requests.push(request);
        let calls = if number == 1 || self.repeat {
            vec![
                ModelToolCall::from_proposal(
                    &format!("query_{number}"),
                    ProposedCall {
                        tool: self.tool.clone(),
                        args: BTreeMap::new(),
                    },
                )
                .unwrap(),
            ]
        } else {
            vec![]
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: if calls.is_empty() {
                    "Completed synthetic review."
                } else {
                    "Read the restricted summary."
                }
                .into(),
                calls,
                raw: "synthetic".into(),
                truncated: false,
            },
            Some(ModelUsage {
                input_tokens: 5,
                output_tokens: 2,
            }),
        ))
    }
}
pub(super) fn start(
    engine: &Engine<'_>,
    history: &History,
) -> irmind_app::subagents::StartedSubagentPlan {
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(100_000)],
            SubagentResources::default(),
            &CancellationToken::new(),
        )
        .unwrap();
    let choice = prepared.preview().automatic_start().unwrap();
    engine
        .admit_subagent_plan(&prepared, &choice, &CancellationToken::new())
        .unwrap()
        .unwrap()
}
pub(super) fn verify_and_export(
    store: &LocalStore,
    engine: &Engine<'_>,
    history: &History,
    root: &std::path::Path,
) {
    engine.verify(&history.case).unwrap();
    engine.seal(&history.case).unwrap();
    let export = root.join("tool-child.irmind");
    CaseExporter::export_case(store, &history.case, &export, &CancellationToken::new()).unwrap();
    verify_export_expected(&export, Some(&hex(&sha256(&history.analyst.public_key())))).unwrap();
}
#[test]
fn subagent_multiple_rounds_return_tool_call_ids_untrusted_results_and_verified_restricted_effects()
{
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let queries = Arc::new(Queries(AtomicUsize::new(0)));
    let (store, engine) =
        stored_history_engine_with_queries(root.path(), &history, &[], queries.clone());
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
    assert_eq!(result.status, SubagentStatus::Completed);
    assert_eq!(result.usage.calls, 1);
    assert_eq!(result.usage.tokens, 14);
    assert_eq!(result.usage.rounds, 2);
    assert_eq!(queries.0.load(Ordering::SeqCst), 1);
    let requests = model.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let messages = &requests[1].messages;
    assert_eq!(messages[2].role, irmind_app::MessageRole::Assistant);
    assert_eq!(messages[2].tool_calls[0].id(), "query_1");
    assert_eq!(messages[3].tool_call_id.as_deref(), Some("query_1"));
    assert!(messages[3].content.starts_with("<UNTRUSTED_"));
    assert!(messages[3].content.contains("Synthetic restricted summary"));
    assert!(
        messages[0]
            .content
            .find("Synthetic restricted summary")
            .is_none()
    );
    drop(requests);
    engine.finish_subagent_plan(&started).unwrap();
    verify_and_export(store.as_ref(), &engine, &history, root.path());
}
#[test]
fn subagent_tool_round_limit_preserves_work_and_disallowed_tools_never_reach_queries() {
    for (tool, expected_calls) in [(Tool::GraphSummary, 2), (Tool::ThreatIntelExternal, 0)] {
        let history = History::new();
        let root = tempfile::tempdir().unwrap();
        let queries = Arc::new(Queries(AtomicUsize::new(0)));
        let (store, engine) =
            stored_history_engine_with_queries(root.path(), &history, &[], queries.clone());
        let started = start(&engine, &history);
        let model = ToolModel {
            requests: std::sync::Mutex::new(vec![]),
            repeat: true,
            tool,
        };
        let result = engine
            .run_subagent_task(
                &started,
                started.plan().tasks[0].task_id,
                &model,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(result.status, SubagentStatus::Partial);
        assert_eq!(result.usage.calls, expected_calls);
        assert_eq!(
            queries.0.load(Ordering::SeqCst),
            usize::try_from(expected_calls).unwrap()
        );
        assert!(!result.coverage.is_empty());
        engine.finish_subagent_plan(&started).unwrap();
        verify_and_export(store.as_ref(), &engine, &history, root.path());
    }
}

struct RepeatedProtocolId;
#[async_trait]
impl LlmPort for RepeatedProtocolId {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic repeated provider identifier".into(),
                calls: vec![
                    ModelToolCall::from_proposal(
                        "same_call",
                        ProposedCall {
                            tool: Tool::GraphSummary,
                            args: BTreeMap::new(),
                        },
                    )
                    .unwrap(),
                ],
                raw: "synthetic".into(),
                truncated: false,
            },
            Some(ModelUsage {
                input_tokens: 5,
                output_tokens: 2,
            }),
        ))
    }
}
#[test]
fn repeated_provider_call_identifier_preserves_a_partial_verifiable_task_without_reexecuting() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let queries = Arc::new(Queries(AtomicUsize::new(0)));
    let (store, engine) =
        stored_history_engine_with_queries(root.path(), &history, &[], queries.clone());
    let started = start(&engine, &history);
    let result = engine
        .run_subagent_task(
            &started,
            started.plan().tasks[0].task_id,
            &RepeatedProtocolId,
            &CancellationToken::new(),
        )
        .unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    verify_and_export(store.as_ref(), &engine, &history, root.path());
    assert_eq!(queries.0.load(Ordering::SeqCst), 1);
    assert_eq!(result.status, SubagentStatus::Partial);
    assert!(
        result
            .coverage
            .iter()
            .any(|text| text.contains("identifier"))
    );
}
