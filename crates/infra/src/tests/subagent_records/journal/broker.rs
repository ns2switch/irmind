mod admissions;
mod events;
mod findings;
mod live_approvals;
mod parallel;
mod pending;
mod recovery;
mod root;
mod scope;
mod skills;
mod tools;
use super::*;
use irmind_app::subagents::{SubagentResources, SubagentTaskProposal};

fn proposal(tokens: u64) -> SubagentTaskProposal {
    SubagentTaskProposal {
        type_id: "triage".into(),
        objective: "Review the synthetic local evidence".into(),
        sources: vec![],
        remote_scope: None,
        skill: None,
        budget: SubagentResources {
            tokens,
            calls: 10,
            rounds: 2,
            cloud_bytes: 0,
        },
    }
}

#[test]
fn subagent_broker_previews_then_requires_real_analyst_consent_above_whole_plan_threshold() {
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
    assert!(prepared.preview().confirmation_required());
    assert!(prepared.preview().automatic_start().is_err());
    assert!(
        !store
            .entries(&history.case)
            .unwrap()
            .iter()
            .any(|entry| entry.kind == AuditEventKind::SubagentPlanApprovalV1)
    );
    let choice = prepared.preview().start().unwrap();
    let started = engine
        .admit_subagent_plan(&prepared, &choice, &cancel)
        .unwrap()
        .unwrap();
    assert_eq!(started.plan().reservation.tokens, 500_001);
    let entries = store.entries(&history.case).unwrap();
    let consent = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SubagentPlanApprovalV1)
        .unwrap();
    assert_eq!(consent.actor, Actor::Analyst);
    verify_subagent_plan_consent(consent, started.plan(), &history.verifier).unwrap();
    assert!(
        engine
            .admit_subagent_plan(&prepared, &choice, &cancel)
            .is_err()
    );
    engine.verify(&history.case).unwrap();
    assert!(engine.seal(&history.case).is_err());
}

#[test]
fn subagent_broker_rechecks_budget_and_cancels_a_stale_preview_without_starting() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(100_000)],
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    assert!(!prepared.preview().confirmation_required());
    assert!(
        engine
            .change_case_budget(
                &history.case,
                irmind_app::CaseBudgetLimits {
                    model_tokens: 50_000,
                    tool_calls: 1000,
                    cloud_bytes: 536_870_912_000
                },
                false
            )
            .is_err()
    );
    engine
        .change_case_budget(
            &history.case,
            irmind_app::CaseBudgetLimits {
                model_tokens: 1_500_000,
                tool_calls: 1000,
                cloud_bytes: 536_870_912_000,
            },
            false,
        )
        .unwrap();
    let choice = prepared.preview().automatic_start().unwrap();
    assert!(
        engine
            .admit_subagent_plan(&prepared, &choice, &cancel)
            .is_err()
    );
    let reject = prepared.preview().cancel().unwrap();
    assert!(
        engine
            .admit_subagent_plan(&prepared, &reject, &cancel)
            .unwrap()
            .is_none()
    );
    let mut journal = SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
    for entry in store.entries(&history.case).unwrap() {
        journal.accept(&entry, &history.verifier).unwrap();
    }
    assert_eq!(journal.outstanding().unwrap(), SubagentResources::default());
    assert!(!journal.has_open_plans().unwrap());
}

#[test]
fn subagent_broker_rejects_unknown_sources_and_keeps_cancelled_previews_out_of_dispatch() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let mut task = proposal(100_000);
    task.sources
        .push(irmind_domain::EvidenceHash::parse(&"11".repeat(32)).unwrap());
    let cancel = CancellationToken::new();
    assert!(
        engine
            .prepare_subagent_plan(
                &history.case,
                "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                vec![task],
                SubagentResources::default(),
                &cancel
            )
            .is_err()
    );
    assert_eq!(store.entries(&history.case).unwrap().len(), 1);
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(100_000)],
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let choice = prepared.preview().automatic_start().unwrap();
    cancel.cancel();
    assert!(
        engine
            .admit_subagent_plan(&prepared, &choice, &cancel)
            .unwrap()
            .is_none()
    );
    engine.verify(&history.case).unwrap();
    engine.seal(&history.case).unwrap();
}

struct ChildModel {
    requests: std::sync::Mutex<Vec<CompletionRequest>>,
    usage: Option<ModelUsage>,
    cancel: bool,
    late: Option<Arc<irmind_testkit::FixedClock>>,
}
#[async_trait]
impl LlmPort for ChildModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        self.requests.lock().unwrap().push(request);
        if self.cancel {
            return Err(AppError::Cancelled);
        }
        if let Some(clock) = &self.late {
            clock.set(1000);
        }
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic bounded result.".into(),
                calls: vec![],
                raw: "synthetic".into(),
                truncated: false,
            },
            self.usage,
        ))
    }
}
fn child_model(usage: bool) -> ChildModel {
    ChildModel {
        requests: std::sync::Mutex::new(vec![]),
        usage: usage.then_some(ModelUsage {
            input_tokens: 5,
            output_tokens: 2,
        }),
        cancel: false,
        late: None,
    }
}

#[test]
fn one_child_reserves_before_model_dispatch_records_branches_and_exports_offline() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(100_000)],
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let choice = prepared.preview().automatic_start().unwrap();
    let started = engine
        .admit_subagent_plan(&prepared, &choice, &cancel)
        .unwrap()
        .unwrap();
    let model = child_model(true);
    let result = engine
        .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
        .unwrap();
    assert_eq!(
        result.status,
        irmind_app::subagents::SubagentStatus::Completed
    );
    assert_eq!(result.usage.tokens, 7);
    assert_eq!(result.usage.rounds, 1);
    let requests = model.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .tools
            .iter()
            .any(|tool| tool.name == "entity_lookup")
    );
    assert!(
        !requests[0]
            .tools
            .iter()
            .any(|tool| matches!(tool.name, "delegate_task" | "ti_lookup_external"))
    );
    let user = &requests[0].messages[1];
    assert_eq!(user.role, irmind_app::MessageRole::User);
    assert!(user.content.contains("<UNTRUSTED_"));
    assert!(user.content.contains("Review the synthetic local evidence"));
    assert!(
        !requests[0].messages[0]
            .content
            .contains("Review the synthetic local evidence")
    );
    drop(requests);
    engine.verify(&history.case).unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    assert!(
        engine
            .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
            .is_err()
    );
    assert!(engine.finish_subagent_plan(&started).is_err());
    engine.seal(&history.case).unwrap();
    let output = root.path().join("child.irmind");
    CaseExporter::export_case(store.as_ref(), &history.case, &output, &cancel).unwrap();
    verify_export_expected(&output, Some(&hex(&sha256(&history.analyst.public_key())))).unwrap();
}

#[test]
fn child_unknown_usage_is_reserved_after_completion_and_cancelled_requests_keep_a_terminal() {
    for cancelled in [false, true] {
        let history = History::new();
        let root = tempfile::tempdir().unwrap();
        let (store, engine) = stored_history_engine(root.path(), &history, &[]);
        let cancel = CancellationToken::new();
        let prepared = engine
            .prepare_subagent_plan(
                &history.case,
                "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                vec![proposal(100_000)],
                SubagentResources::default(),
                &cancel,
            )
            .unwrap();
        let choice = prepared.preview().automatic_start().unwrap();
        let started = engine
            .admit_subagent_plan(&prepared, &choice, &cancel)
            .unwrap()
            .unwrap();
        let mut model = child_model(false);
        model.cancel = cancelled;
        let result = engine
            .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
            .unwrap();
        assert_eq!(
            result.status,
            if cancelled {
                irmind_app::subagents::SubagentStatus::Cancelled
            } else {
                irmind_app::subagents::SubagentStatus::Completed
            }
        );
        assert!(result.usage.tokens > 0);
        engine.finish_subagent_plan(&started).unwrap();
        let entries = store.entries(&history.case).unwrap();
        let mut journal =
            SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
        for entry in &entries {
            journal.accept(entry, &history.verifier).unwrap();
        }
        assert!(!journal.has_open_plans().unwrap());
        assert_eq!(journal.outstanding().unwrap().tokens, result.usage.tokens);
        let budget = engine.case_budget(&history.case).unwrap();
        assert!(!budget.usage.provider_usage_available);
        assert_eq!(budget.usage.cost_microusd, None);
        engine.seal(&history.case).unwrap();
    }
}

#[test]
fn a_child_deadline_records_cleanup_at_the_real_time_without_accepting_late_content() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (_, mut engine) = stored_history_engine(root.path(), &history, &[]);
    let clock = Arc::new(irmind_testkit::FixedClock::new(10));
    engine.clock = clock.clone();
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(100_000)],
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let choice = prepared.preview().automatic_start().unwrap();
    let started = engine
        .admit_subagent_plan(&prepared, &choice, &cancel)
        .unwrap()
        .unwrap();
    let mut model = child_model(true);
    model.late = Some(clock);
    let result = engine
        .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
        .unwrap();
    assert_eq!(
        result.status,
        irmind_app::subagents::SubagentStatus::Cancelled
    );
    assert!(!result.guarded_summary.contains("Synthetic bounded result"));
    assert_eq!(result.usage.tokens, 7);
    engine.verify(&history.case).unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    engine.seal(&history.case).unwrap();
}

#[test]
fn a_valid_agent_signature_cannot_reserve_new_model_work_after_the_task_deadline() {
    let mut history = History::new();
    let plan = history.plan(100_000);
    let plan_hash = history.record(&plan, false);
    let hold = transition(&plan, ReservationAction::HoldPreview, None, plan_hash);
    history.record(&hold, false);
    let start = transition(
        &plan,
        ReservationAction::StartPlan,
        Some(hold.operation_id),
        plan_hash,
    );
    history.record(&start, false);
    let request = SubagentReservationV1::prepare(
        &plan,
        Some(plan.tasks[0].task_id),
        1,
        ReservationAction::ReserveRequest,
        ReservationPurpose::Model,
        ReservationTransition {
            amount: SubagentResources {
                tokens: 100,
                rounds: 1,
                calls: 0,
                cloud_bytes: 0,
            },
            parent_operation: Some(start.operation_id),
            cause_sha256: plan_hash,
            accounting_audit_sha256: None,
        },
    )
    .unwrap();
    history.record(&request, false);
    assert!(history.replay().is_ok());
    let entry = history.entries.last_mut().unwrap();
    entry.at = plan.tasks[0].deadline_at + 1;
    entry.hash = sha256(&entry.canonical());
    entry.sig = history.agent.sign(&entry.hash).unwrap();
    assert!(history.replay().is_err());
}
