use super::*;
use irmind_app::subagents::{
    AnalystPlanChoice, AnalystPlanInteraction, PortFuture, SafePlanPreview,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Review {
    seen: AtomicUsize,
    reject: bool,
    expected_confirmation: bool,
}
impl AnalystPlanInteraction for Review {
    fn review<'a>(
        &'a self,
        preview: &'a SafePlanPreview,
        _: &'a CancellationToken,
    ) -> PortFuture<'a, AnalystPlanChoice> {
        Box::pin(async move {
            self.seen.fetch_add(1, Ordering::SeqCst);
            assert_eq!(preview.tasks().len(), 2);
            assert_eq!(preview.confirmation_required(), self.expected_confirmation);
            if self.reject {
                preview.cancel()
            } else if preview.confirmation_required() {
                preview.start()
            } else {
                preview.automatic_start()
            }
        })
    }
}

struct DelegatingModel {
    root_rounds: AtomicUsize,
    children: AtomicUsize,
    child_tokens: u64,
    repeat_plan: bool,
    child_delegates: bool,
    inject_confirmation: bool,
    store: Arc<LocalStore>,
    case: CaseId,
}
impl DelegatingModel {
    fn child_reply(
        &self,
        request: &CompletionRequest,
    ) -> Result<(&'static str, Vec<ModelToolCall>), AppError> {
        self.children.fetch_add(1, Ordering::SeqCst);
        assert!(
            !request
                .tools
                .iter()
                .any(|tool| tool.name == "delegate_task")
        );
        // Each child can acquire the transaction lock: the parent cannot
        // retain it while awaiting model work.
        let _lock = self.store.lock_case(&self.case)?;
        Ok((
            "Synthetic bounded child result.",
            if self.child_delegates {
                vec![
                    ModelToolCall::from_proposal(
                        "recursive_plan",
                        ProposedCall {
                            tool: Tool::DelegateTask,
                            args: BTreeMap::from([("tasks".into(), "[]".into())]),
                        },
                    )
                    .unwrap(),
                ]
            } else {
                vec![]
            },
        ))
    }
}
#[async_trait]
impl LlmPort for DelegatingModel {
    fn output_profile(&self) -> irmind_app::ModelOutputProfile {
        irmind_app::ModelOutputProfile::known(2048, false).unwrap()
    }
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let child = request.messages[0]
            .content
            .contains("You are an IRMind subagent");
        let (text, calls) = if child {
            self.child_reply(&request)?
        } else if self.root_rounds.fetch_add(1, Ordering::SeqCst) <= usize::from(self.repeat_plan) {
            assert!(
                request
                    .tools
                    .iter()
                    .any(|tool| tool.name == "delegate_task")
            );
            let mut proposed = serde_json::json!([
                {"type_id":"triage","objective":"Review synthetic Windows evidence", "sources":[],"remote_scope":null,"skill":null,"budget":{"tokens":self.child_tokens,"calls":1,"rounds":1,"cloud_bytes":0}},
                {"type_id":"cloud","objective":"Review synthetic AWS evidence", "sources":[],"remote_scope":null,"skill":null,"budget":{"tokens":self.child_tokens,"calls":1,"rounds":1,"cloud_bytes":0}}
            ]);
            if self.inject_confirmation {
                proposed[0]["confirmed"] = serde_json::json!(true);
            }
            let tasks = serde_json::to_string(&proposed).unwrap();
            (
                "Propose a bounded parallel plan.",
                vec![
                    ModelToolCall::from_proposal(
                        "plan_1",
                        ProposedCall {
                            tool: Tool::DelegateTask,
                            args: BTreeMap::from([("tasks".into(), tasks)]),
                        },
                    )
                    .unwrap(),
                ],
            )
        } else {
            assert!(
                request
                    .messages
                    .iter()
                    .any(|message| message.role == irmind_app::MessageRole::Tool
                        && message.tool_call_id.as_deref() == Some("plan_1")
                        && message.content.contains("<UNTRUSTED_"))
            );
            ("Synthetic parent summary.", vec![])
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: text.into(),
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
fn parent_delegation_shows_one_whole_plan_releases_its_lock_and_returns_untrusted_children() {
    for (tokens, reject, required) in [
        (30_000, false, false),
        (300_000, false, true),
        (300_000, true, true),
    ] {
        let history = History::new();
        let root = tempfile::tempdir().unwrap();
        let review = Arc::new(Review {
            seen: AtomicUsize::new(0),
            reject,
            expected_confirmation: required,
        });
        let (store, engine) = stored_history_engine_with_interaction(
            root.path(),
            &history,
            &[],
            Arc::new(NoTaskQueries),
            review.clone(),
        );
        let model = DelegatingModel {
            root_rounds: AtomicUsize::new(0),
            children: AtomicUsize::new(0),
            child_tokens: tokens,
            repeat_plan: false,
            child_delegates: false,
            inject_confirmation: false,
            store: store.clone(),
            case: history.case.clone(),
        };
        let answer = engine
            .investigate(
                &history.case,
                "Review these independent synthetic sources",
                &model,
            )
            .unwrap();
        assert_eq!(answer, "Synthetic parent summary.");
        assert_eq!(review.seen.load(Ordering::SeqCst), 1);
        assert_eq!(
            model.children.load(Ordering::SeqCst),
            if reject { 0 } else { 2 }
        );
        let entries = store.entries(&history.case).unwrap();
        let approvals = entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SubagentPlanApprovalV1)
            .collect::<Vec<_>>();
        assert_eq!(approvals.len(), usize::from(required));
        assert!(approvals.iter().all(|entry| entry.actor == Actor::Analyst));
        let mut journal =
            SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
        for entry in &entries {
            journal.accept(entry, &history.verifier).unwrap();
        }
        assert!(!journal.has_open_plans().unwrap());
        assert_eq!(journal.outstanding().unwrap(), SubagentResources::default());
        tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
    }
}

#[test]
fn repeated_parent_delegation_reuses_its_result_and_children_share_the_parent_round_limit() {
    for limit in [3, 25] {
        let history = History::new();
        let root = tempfile::tempdir().unwrap();
        let review = Arc::new(Review {
            seen: AtomicUsize::new(0),
            reject: false,
            expected_confirmation: false,
        });
        let (store, engine) = stored_history_engine_with_interaction(
            root.path(),
            &history,
            &[],
            Arc::new(NoTaskQueries),
            review.clone(),
        );
        let engine = engine
            .with_policy(
                PolicyRules {
                    max_model_rounds_per_turn: limit,
                    ..PolicyRules::default()
                },
                "a".repeat(64),
            )
            .unwrap();
        let model = DelegatingModel {
            root_rounds: AtomicUsize::new(0),
            children: AtomicUsize::new(0),
            child_tokens: 30_000,
            repeat_plan: true,
            child_delegates: false,
            inject_confirmation: false,
            store: store.clone(),
            case: history.case.clone(),
        };
        let answer = engine
            .investigate(
                &history.case,
                "Review independent synthetic evidence",
                &model,
            )
            .unwrap();
        assert_eq!(review.seen.load(Ordering::SeqCst), 1);
        assert_eq!(model.children.load(Ordering::SeqCst), 2);
        assert_eq!(
            model.root_rounds.load(Ordering::SeqCst),
            if limit == 3 { 1 } else { 3 }
        );
        if limit == 3 {
            assert!(answer.contains("Recorded work:"));
        } else {
            assert_eq!(answer, "Synthetic parent summary.");
        }
        let entries = store.entries(&history.case).unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.kind == AuditEventKind::SubagentPlanV2)
                .count(),
            1
        );
        tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
    }
}

#[test]
fn manufactured_confirmation_is_not_a_start_and_children_cannot_delegate() {
    for injected in [true, false] {
        let history = History::new();
        let root = tempfile::tempdir().unwrap();
        let review = Arc::new(Review {
            seen: AtomicUsize::new(0),
            reject: false,
            expected_confirmation: true,
        });
        let (store, engine) = stored_history_engine_with_interaction(
            root.path(),
            &history,
            &[],
            Arc::new(NoTaskQueries),
            review.clone(),
        );
        let model = DelegatingModel {
            root_rounds: AtomicUsize::new(0),
            children: AtomicUsize::new(0),
            child_tokens: 300_000,
            repeat_plan: false,
            child_delegates: !injected,
            inject_confirmation: injected,
            store: store.clone(),
            case: history.case.clone(),
        };
        engine
            .investigate(
                &history.case,
                "Review independent synthetic sources",
                &model,
            )
            .unwrap();
        let entries = store.entries(&history.case).unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.kind == AuditEventKind::SubagentPlanV2)
                .count(),
            usize::from(!injected)
        );
        assert_eq!(review.seen.load(Ordering::SeqCst), usize::from(!injected));
        if !injected {
            let results = entries
                .iter()
                .filter(|entry| entry.kind == AuditEventKind::SubagentResultV1)
                .map(|entry| {
                    irmind_app::subagents::SubagentResultV1::decode(
                        &hex::decode(entry.payload.split_once(':').unwrap().1).unwrap(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(results.len(), 2);
            assert!(results.iter().all(|result| result.status
                == irmind_app::subagents::SubagentStatus::Partial
                && result.usage.calls == 0));
        }
        tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
    }
}
