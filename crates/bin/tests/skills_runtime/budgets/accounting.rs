use super::{BudgetModel, setup};
use irmind_app::AuditLog;
use irmind_domain::AuditEventKind;
#[test]
fn malformed_usage_is_rejected_before_a_receipt_can_invalidate_the_case() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let case = engine
        .create_case("Synthetic usage validation", "local")
        .unwrap();
    let model = BudgetModel {
        requests: std::sync::Mutex::default(),
        output: Some("Synthetic reply."),
        usage: Some(irmind_app::ModelUsage {
            input_tokens: u64::MAX,
            output_tokens: 1,
        }),
    };
    assert!(
        engine
            .investigate(&case.id, "Discuss this synthetic case.", &model)
            .is_err()
    );
    assert!(
        !store
            .entries(&case.id)
            .unwrap()
            .iter()
            .any(|e| e.kind == AuditEventKind::ModelUsage)
    );
    engine.verify(&case.id).unwrap();
}

#[test]
fn cumulative_cost_overflow_is_rejected_before_publishing_an_invalid_receipt() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let engine = engine.with_pricing(irmind_app::ModelPricing {
        input_microusd_per_million: 1_000_000_000_000,
        output_microusd_per_million: 1_000_000_000_000,
    });
    let case = engine
        .create_case("Synthetic cost accounting", "local")
        .unwrap();
    let model = BudgetModel {
        requests: std::sync::Mutex::default(),
        output: Some("Synthetic reply."),
        usage: Some(irmind_app::ModelUsage {
            input_tokens: 8,
            output_tokens: 2,
        }),
    };
    engine
        .investigate(&case.id, "Discuss the local case.", &model)
        .unwrap();
    let invalid = BudgetModel {
        requests: std::sync::Mutex::default(),
        output: Some("Synthetic reply."),
        usage: Some(irmind_app::ModelUsage {
            input_tokens: 18_446_744_073_709,
            output_tokens: 0,
        }),
    };
    assert!(
        engine
            .investigate(&case.id, "Continue the discussion.", &invalid)
            .is_err()
    );
    assert_eq!(
        store
            .entries(&case.id)
            .unwrap()
            .iter()
            .filter(|e| e.kind == AuditEventKind::ModelUsage)
            .count(),
        1
    );
    engine.verify(&case.id).unwrap();
}

#[test]
fn recovery_lists_each_changed_case_default_before_signed_acceptance() {
    use irmind_app::{CaseBudgetLimits, ConfigChange, ConfigurationInspection, ConfigurationStore};
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path());
    let config = irmind_infra::TomlConfigurationStore::new(root.path());
    engine.verify_configuration(&config, &[]).unwrap();
    engine
        .apply_configuration_change(
            &config,
            &[],
            ConfigChange::SetCaseBudgetDefaults(super::limits(3000, 10)),
            true,
        )
        .unwrap();
    let mut edited = config.load().unwrap();
    edited.case_budget_defaults = Some(CaseBudgetLimits {
        model_tokens: 4000,
        tool_calls: 20,
        cloud_bytes: 2_147_483_648,
    });
    config.save(&edited).unwrap();
    let review = match engine.inspect_configuration(&config, &[], true).unwrap() {
        ConfigurationInspection::Review(review) => Some(review),
        ConfigurationInspection::Current => None,
    }
    .unwrap();
    let fields = review
        .differences
        .iter()
        .map(|d| d.field.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        [
            "case_budget_defaults.cloud_bytes",
            "case_budget_defaults.model_tokens",
            "case_budget_defaults.tool_calls"
        ]
    );
    engine
        .accept_current_configuration(&config, &[], true, true)
        .unwrap();
    engine.verify_configuration(&config, &[]).unwrap();
}
