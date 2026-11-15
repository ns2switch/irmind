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
