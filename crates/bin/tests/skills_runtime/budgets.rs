mod accounting;
mod cloud;
mod model;
mod unallocated;
use super::setup;
use irmind_app::{AuditLog, CancellationToken, CaseBudgetLimits, ProposedCall};
use irmind_domain::{AuditEventKind, PolicyRules, Tool};
use model::BudgetModel;
use std::collections::BTreeMap;

fn limits(tokens: u64, calls: u64) -> CaseBudgetLimits {
    CaseBudgetLimits {
        model_tokens: tokens,
        tool_calls: calls,
        cloud_bytes: 1_073_741_824,
    }
}
#[test]
fn case_allocations_are_signed_and_increases_require_confirmation_under_the_ceiling() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let engine = engine.with_case_budget_defaults(limits(200, 2)).unwrap();
    let case = engine.create_case("Signed allocation", "local").unwrap();
    let initial = engine.case_budget(&case.id).unwrap();
    assert_eq!(initial.allocated, Some(limits(200, 2)));
    let before = store.entries(&case.id).unwrap().len();
    assert!(
        engine
            .change_case_budget(&case.id, limits(400, 4), false)
            .is_err()
    );
    assert_eq!(store.entries(&case.id).unwrap().len(), before);
    engine
        .change_case_budget(&case.id, limits(400, 4), true)
        .unwrap();
    let status = engine.case_budget(&case.id).unwrap();
    assert_eq!(status.allocated, Some(limits(400, 4)));
    assert_eq!(status.usage.tool_calls, 0);
    let last = store.entries(&case.id).unwrap().pop().unwrap();
    assert_eq!(last.kind, AuditEventKind::CaseBudgetChanged);
    assert_eq!(last.actor, irmind_domain::Actor::Analyst);
    engine.verify(&case.id).unwrap();
    assert!(
        engine
            .change_case_budget(&case.id, limits(2_000_001, 4), true)
            .is_err()
    );
}
#[test]
fn quota_consumption_survives_changes_and_new_defaults_do_not_change_existing_cases() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path());
    let engine = engine.with_case_budget_defaults(limits(2_000, 1)).unwrap();
    let case = engine.create_case("Limited tool calls", "local").unwrap();
    let call = || ProposedCall {
        tool: Tool::GraphSummary,
        args: BTreeMap::new(),
    };
    engine
        .request_tool_as_analyst(&case.id, call(), &CancellationToken::new())
        .unwrap();
    let denied = engine
        .request_tool_as_analyst(&case.id, call(), &CancellationToken::new())
        .unwrap();
    assert!(denied.contains("quota"));
    let status = engine.case_budget(&case.id).unwrap();
    assert_eq!(status.usage.tool_calls, 1);
    assert!(status.warning());
    let engine = engine.with_case_budget_defaults(limits(5_000, 5)).unwrap();
    assert_eq!(
        engine
            .case_budget(&case.id)
            .unwrap()
            .allocated
            .unwrap()
            .tool_calls,
        1
    );
    let other = engine.create_case("Later defaults", "local").unwrap();
    assert_eq!(
        engine
            .case_budget(&other.id)
            .unwrap()
            .allocated
            .unwrap()
            .tool_calls,
        5
    );
    engine
        .change_case_budget(&case.id, limits(2_000, 2), true)
        .unwrap();
    engine
        .request_tool_as_analyst(&case.id, call(), &CancellationToken::new())
        .unwrap();
    assert_eq!(engine.case_budget(&case.id).unwrap().usage.tool_calls, 2);
    assert!(
        engine
            .change_case_budget(&case.id, limits(2_000, 1), true)
            .is_err()
    );
}
#[test]
fn organization_ceiling_clips_new_allocations_and_cannot_be_overridden_by_approval() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path());
    let policy = PolicyRules {
        max_model_tokens_per_case: 100,
        max_tool_calls_per_case: 2,
        ..PolicyRules::default()
    };
    let engine = engine.with_policy(policy, "ab".repeat(32)).unwrap();
    let case = engine.create_case("Strict organization", "local").unwrap();
    let status = engine.case_budget(&case.id).unwrap();
    assert_eq!(status.effective.unwrap().model_tokens, 100);
    assert_eq!(status.effective.unwrap().tool_calls, 2);
    assert!(
        engine
            .change_case_budget(&case.id, limits(101, 2), true)
            .is_err()
    );
    engine.seal(&case.id).unwrap();
    assert!(
        engine
            .change_case_budget(&case.id, limits(99, 1), true)
            .is_err()
    );
}

#[test]
fn exhausted_tool_allocation_finishes_with_a_tool_free_summary() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path());
    let engine = engine.with_case_budget_defaults(limits(2_000, 1)).unwrap();
    let case = engine
        .create_case("Budgeted synthetic investigation", "local")
        .unwrap();
    let model = BudgetModel {
        requests: std::sync::Mutex::default(),
        output: None,
        usage: Some(irmind_app::ModelUsage {
            input_tokens: 8,
            output_tokens: 2,
        }),
    };
    let answer = engine
        .investigate(&case.id, "Review the local synthetic evidence.", &model)
        .unwrap();
    assert!(answer.contains("Completed local evidence review."));
    assert!(answer.contains("calls 1/1"));
    assert!(answer.contains("/budget"));
    let requests = model.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].tools.is_empty());
    assert!(
        requests
            .iter()
            .flat_map(|r| &r.messages)
            .filter(|m| m.role == irmind_app::MessageRole::System)
            .all(|m| !m.content.contains(&case.title))
    );
    let status = engine.case_budget(&case.id).unwrap();
    assert_eq!(status.usage.model_tokens, 20);
    assert_eq!(status.usage.tool_calls, 1);
    engine.verify(&case.id).unwrap();
}
#[test]
fn exhausted_tokens_preserve_local_work_without_an_additional_model_request() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path());
    let engine = engine.with_case_budget_defaults(limits(10, 5)).unwrap();
    let case = engine
        .create_case("Synthetic token boundary", "local")
        .unwrap();
    let model = BudgetModel {
        requests: std::sync::Mutex::default(),
        output: None,
        usage: Some(irmind_app::ModelUsage {
            input_tokens: 8,
            output_tokens: 2,
        }),
    };
    let answer = engine
        .investigate(&case.id, "Review the local evidence.", &model)
        .unwrap();
    assert!(answer.contains("Recorded work:"));
    assert!(answer.contains("Recorded tokens 10/10"));
    assert_eq!(model.requests.lock().unwrap().len(), 1);
    assert_eq!(engine.case_budget(&case.id).unwrap().usage.tool_calls, 0);
}
#[test]
fn model_text_cannot_apply_a_budget_command_and_restart_preserves_the_allocation() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let engine = engine.with_case_budget_defaults(limits(2_000, 5)).unwrap();
    let case = engine
        .create_case("No model budget authority", "local")
        .unwrap();
    let model = BudgetModel {
        requests: std::sync::Mutex::default(),
        output: Some("/budget 10000000"),
        usage: Some(irmind_app::ModelUsage {
            input_tokens: 8,
            output_tokens: 2,
        }),
    };
    engine
        .investigate(&case.id, "Discuss the investigation budget.", &model)
        .unwrap();
    assert!(
        !model
            .requests
            .lock()
            .unwrap()
            .iter()
            .flat_map(|r| &r.tools)
            .any(|t| t.name.contains("budget"))
    );
    let (_, restarted) = super::setup_with_store(root.path(), store.clone(), false);
    let status = restarted.case_budget(&case.id).unwrap();
    assert_eq!(status.allocated.unwrap().model_tokens, 2_000);
    assert_eq!(status.usage.model_tokens, 10);
    assert!(
        !store
            .entries(&case.id)
            .unwrap()
            .iter()
            .any(|e| e.kind == AuditEventKind::CaseBudgetChanged)
    );
}
#[test]
fn signed_new_case_defaults_are_persistent_and_reject_the_organization_ceiling() {
    use irmind_app::{ConfigChange, ConfigurationStore};
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path());
    let config = irmind_infra::TomlConfigurationStore::new(root.path());
    engine.verify_configuration(&config, &[]).unwrap();
    engine
        .apply_configuration_change(
            &config,
            &[],
            ConfigChange::SetCaseBudgetDefaults(limits(3_000, 10)),
            true,
        )
        .unwrap();
    let saved = config.load().unwrap();
    assert_eq!(saved.case_budget_defaults, Some(limits(3_000, 10)));
    assert!(
        engine
            .apply_configuration_change(
                &config,
                &[],
                ConfigChange::SetCaseBudgetDefaults(limits(2_000_001, 10)),
                true
            )
            .is_err()
    );
    assert_eq!(
        config.load().unwrap().case_budget_defaults,
        saved.case_budget_defaults
    );
    engine.verify_configuration(&config, &[]).unwrap();
}

#[test]
fn a_failed_budget_signature_does_not_publish_any_change() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let mut engine = engine.with_case_budget_defaults(limits(100, 2)).unwrap();
    let case = engine
        .create_case("Atomic budget signing", "local")
        .unwrap();
    let before = store.entries(&case.id).unwrap().len();
    engine.signer = std::sync::Arc::new(super::FixedSigner(
        irmind_domain::Actor::Analyst,
        super::SigningKey::from_bytes(&[73; 32]),
        true,
    ));
    assert!(
        engine
            .change_case_budget(&case.id, limits(200, 3), true)
            .is_err()
    );
    assert_eq!(store.entries(&case.id).unwrap().len(), before);
    assert_eq!(
        engine.case_budget(&case.id).unwrap().allocated,
        Some(limits(100, 2))
    );
}

#[test]
fn insufficient_compaction_budget_preserves_history_and_finishes_locally() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path());
    let engine = engine.with_case_budget_defaults(limits(20_000, 5)).unwrap();
    let case = engine
        .create_case("Synthetic long history", "local")
        .unwrap();
    let answer = Box::leak("synthetic observation ".repeat(450).into_boxed_str());
    let model = BudgetModel {
        requests: std::sync::Mutex::default(),
        output: Some(answer),
        usage: Some(irmind_app::ModelUsage {
            input_tokens: 8,
            output_tokens: 2,
        }),
    };
    for _ in 0..5 {
        engine
            .investigate(&case.id, "Review this synthetic observation.", &model)
            .unwrap();
    }
    let used = engine.case_budget(&case.id).unwrap().usage.model_tokens;
    engine
        .change_case_budget(&case.id, limits(used + 100, 5), true)
        .unwrap();
    let requests = model.requests.lock().unwrap().len();
    let reply = engine
        .investigate(&case.id, "Continue the review.", &model)
        .unwrap();
    assert!(reply.contains("cannot cover history compaction"));
    assert!(reply.contains("Recorded work:"));
    assert_eq!(model.requests.lock().unwrap().len(), requests);
    engine.verify(&case.id).unwrap();
}

#[test]
fn a_signed_case_budget_survives_sealing_and_public_export_verification() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let engine = engine.with_case_budget_defaults(limits(1_000, 2)).unwrap();
    let case = engine
        .create_case("Synthetic budget export", "local")
        .unwrap();
    engine
        .change_case_budget(&case.id, limits(2_000, 3), true)
        .unwrap();
    engine.seal(&case.id).unwrap();
    let destination = root.path().join("budget.irmind");
    let key = irmind_app::export_case_with_originals(
        &engine,
        store.as_ref(),
        &case.id,
        &destination,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let details = irmind_app::verify_export_details(
        &irmind_infra::LocalExportVerifier,
        &destination,
        Some(&key),
    )
    .unwrap();
    assert_eq!(details.format_version, 7);
    if std::env::var_os("IRMIND_REFRESH_SKILL_EXPORT_SEEDS").is_some() {
        std::fs::copy(
            destination,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fuzz/seeds/export/valid-v7-budget.irmind"),
        )
        .unwrap();
    }
}
