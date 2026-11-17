use super::*;
use irmind_app::subagents::SubagentStatus;

struct LongChild {
    text: String,
    maximum: Option<u32>,
    usage: ModelUsage,
    calls: std::sync::atomic::AtomicUsize,
    native_stop: bool,
}
#[async_trait]
impl LlmPort for LongChild {
    fn output_profile(&self) -> irmind_app::ModelOutputProfile {
        irmind_app::ModelOutputProfile {
            maximum_output_tokens: self.maximum.and_then(std::num::NonZeroU32::new),
            parameter_requirement: irmind_app::OutputParameterRequirement::Optional,
        }
    }
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        let first = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
        if self.native_stop && !first {
            assert!(request.tools.is_empty());
        }
        let text = if self.native_stop && !first {
            ". Done.".to_owned()
        } else {
            self.text.clone()
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: text.clone(),
                raw: text,
                truncated: self.native_stop,
                calls: vec![],
            },
            Some(self.usage),
        ))
    }
}

#[test]
fn a_long_child_answer_stays_complete_in_its_branch_with_a_bounded_parent_summary() {
    exercise_child(
        Some(128_000),
        300_000,
        128_000,
        &"word ".repeat(128_000),
        true,
    );
}
#[test]
fn a_reported_child_overrun_is_charged_and_releases_no_spent_capacity() {
    exercise_child(
        Some(2048),
        100_000,
        150_000,
        "The paid child answer is complete.",
        true,
    );
}
#[test]
fn an_unknown_or_insufficient_model_maximum_never_starts_a_child_request() {
    exercise_child(None, 100_000, 0, "No request", false);
    exercise_child(Some(128_000), 100_000, 0, "No request", false);
}
fn exercise_child(
    maximum: Option<u32>,
    allocation: u64,
    output_tokens: u64,
    text: &str,
    starts: bool,
) {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(allocation)],
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let choice = prepared.preview().automatic_start().unwrap();
    let started = engine
        .admit_subagent_plan(&prepared, &choice, &cancel)
        .unwrap()
        .unwrap();
    let model = LongChild {
        text: text.to_owned(),
        maximum,
        usage: ModelUsage {
            cache: Some(
                irmind_app::CacheUsage::new(10, 0, irmind_app::CacheWriteLifetime::NotApplicable)
                    .unwrap(),
            ),
            input_tokens: 20,
            output_tokens,
        },
        calls: std::sync::atomic::AtomicUsize::new(0),
        native_stop: false,
    };
    let result = engine
        .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
        .unwrap();
    assert_eq!(
        model.calls.load(std::sync::atomic::Ordering::SeqCst),
        usize::from(starts)
    );
    assert!(result.guarded_summary.len() <= 16 * 1024);
    if starts {
        assert_eq!(result.usage.tokens, output_tokens + 20);
    } else {
        assert_eq!(result.status, SubagentStatus::Partial);
    }
    engine.verify(&history.case).unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    engine.verify(&history.case).unwrap();
    engine.seal(&history.case).unwrap();
    let path = root.path().join("full-child.irmind");
    CaseExporter::export_case(store.as_ref(), &history.case, &path, &cancel).unwrap();
    verify_export_expected(&path, Some(&hex(&sha256(&history.analyst.public_key())))).unwrap();
    if starts {
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.windows(text.len()).any(|w| w == text.as_bytes()));
    }
}

#[test]
fn a_long_child_native_stop_can_continue_once_without_unbounding_its_context() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let mut task = proposal(400_000);
    task.budget.rounds = 3;
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![task],
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let choice = prepared.preview().automatic_start().unwrap();
    let started = engine
        .admit_subagent_plan(&prepared, &choice, &cancel)
        .unwrap()
        .unwrap();
    let model = LongChild {
        text: "word ".repeat(128_000),
        maximum: Some(128_000),
        usage: ModelUsage {
            cache: None,
            input_tokens: 20,
            output_tokens: 128_000,
        },
        calls: std::sync::atomic::AtomicUsize::new(0),
        native_stop: true,
    };
    let result = engine
        .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
        .unwrap();
    assert_eq!(model.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(result.usage.tokens, 256_040);
    assert!(result.guarded_summary.len() <= 16 * 1024);
    engine.verify(&history.case).unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    engine.seal(&history.case).unwrap();
    let path = root.path().join("continued-child.irmind");
    CaseExporter::export_case(store.as_ref(), &history.case, &path, &cancel).unwrap();
    verify_export_expected(&path, Some(&hex(&sha256(&history.analyst.public_key())))).unwrap();
}
