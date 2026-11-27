use super::*;

#[test]
fn reported_model_overrun_has_a_canonical_receipt_and_exact_material_binding() {
    let usage = ModelUsage {
        cache: None,
        input_tokens: 20,
        output_tokens: 150_000,
    };
    let (history, chunks, _, _, terminal) = completed_model_history_with_usage(usage, Some(usage));
    let journal = history.journal().unwrap();
    supply_material(&journal, &history, &chunks)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(terminal.usage.tokens, 150_020);
    let entry = history
        .entries
        .iter()
        .find(|e| {
            e.kind == AuditEventKind::SubagentReservationV1 && {
                let bytes = hex::decode(e.payload.split_once(':').unwrap().1).unwrap();
                SubagentReservationV1::decode(&bytes).unwrap().action
                    == ReservationAction::SettleRequest
            }
        })
        .unwrap();
    let bytes = hex::decode(entry.payload.split_once(':').unwrap().1).unwrap();
    let receipt = SubagentReservationV1::decode(&bytes).unwrap();
    assert_eq!(receipt.amount.tokens, 150_020);
    let vector = serde_json::json!({"reserved_request_tokens":100,"reported_input_tokens":20,"reported_output_tokens":150_000,"child_allocation_tokens":100_000,"released_token_capacity":0,"receipt":serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),"canonical_hex":hex(&bytes),"receipt_identity":hex(receipt.identity().unwrap().as_bytes())});
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/development/model-output-vectors/overrun-case-v8.json");
    if std::env::var_os("IRMIND_UPDATE_MODEL_OUTPUT_VECTORS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&vector).unwrap()),
        )
        .unwrap();
    }
    let golden: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(vector, golden);
}

#[test]
fn an_overrun_requires_matching_reported_components_not_just_the_same_total() {
    let reported = ModelUsage {
        cache: None,
        input_tokens: 20,
        output_tokens: 150_000,
    };
    for reply in [
        None,
        Some(ModelUsage {
            cache: None,
            input_tokens: 21,
            output_tokens: 149_999,
        }),
    ] {
        let (history, chunks, _, _, _) = completed_model_history_with_usage(reported, reply);
        let journal = history.journal().unwrap();
        assert!(
            supply_material(&journal, &history, &chunks)
                .and_then(irmind_app::subagents::BranchMaterialVerifier::finish)
                .is_err()
        );
    }
}

#[test]
fn token_debt_rejects_a_new_request_before_the_terminal_result_is_merged() {
    let usage = ModelUsage {
        cache: None,
        input_tokens: 20,
        output_tokens: 150_000,
    };
    let (mut history, _, before_result, checkpoint, _) =
        completed_model_history_with_usage(usage, Some(usage));
    history.entries.truncate(before_result);
    let entry = history
        .entries
        .iter()
        .find(|e| e.kind == AuditEventKind::SubagentPlanV2)
        .unwrap();
    let plan =
        SubagentPlanV2::decode(&hex::decode(entry.payload.split_once(':').unwrap().1).unwrap())
            .unwrap();
    let request = SubagentReservationV1::prepare(
        &plan,
        Some(plan.tasks[0].task_id),
        2,
        ReservationAction::ReserveRequest,
        ReservationPurpose::Model,
        ReservationTransition {
            amount: SubagentResources {
                tokens: 1,
                rounds: 1,
                ..SubagentResources::default()
            },
            parent_operation: Some(SubagentReservationV1::operation_id(
                plan.plan_id,
                None,
                ReservationAction::StartPlan,
                ReservationPurpose::Plan,
                0,
            )),
            cause_sha256: checkpoint.identity().unwrap(),
            accounting_audit_sha256: None,
        },
    )
    .unwrap();
    history.record(&request, false);
    assert!(history.replay().is_err());
}

#[test]
fn cache_breakdown_binds_child_reply_receipt_and_settlement() {
    use irmind_app::{CacheUsage, CacheWriteLifetime};
    let usage = ModelUsage {
        input_tokens: 1000,
        output_tokens: 50,
        cache: Some(CacheUsage::new(800, 100, CacheWriteLifetime::FiveMinutes).unwrap()),
    };
    let (history, chunks, _, _, _) = completed_model_history_with_usage(usage, Some(usage));
    supply_material(&history.journal().unwrap(), &history, &chunks)
        .unwrap()
        .finish()
        .unwrap();
    let settlement = history
        .entries
        .iter()
        .find(|e| {
            e.kind == AuditEventKind::SubagentReservationV1 && {
                let bytes = hex::decode(e.payload.split_once(':').unwrap().1).unwrap();
                SubagentReservationV1::decode(&bytes).unwrap().action
                    == ReservationAction::SettleRequest
            }
        })
        .unwrap();
    let vector = serde_json::json!({"reply_usage":usage,"accounting_payload":history.entries.iter().find(|e|e.kind==AuditEventKind::ModelUsage).unwrap().payload,"settlement_payload":settlement.payload,"settlement_entry_sha256":hex(&settlement.hash)});
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/development/context-cost-data/child-cache-settlement-case-v8.json");
    if std::env::var_os("IRMIND_UPDATE_CACHE_VECTORS").is_some() {
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&vector).unwrap()),
        )
        .unwrap();
    }
    let golden: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(vector, golden);
    for cache in [
        None,
        Some(CacheUsage::new(700, 200, CacheWriteLifetime::FiveMinutes).unwrap()),
        Some(CacheUsage::new(800, 100, CacheWriteLifetime::OneHour).unwrap()),
    ] {
        let (history, chunks, _, _, _) =
            completed_model_history_with_usage(usage, Some(ModelUsage { cache, ..usage }));
        assert!(
            supply_material(&history.journal().unwrap(), &history, &chunks)
                .and_then(irmind_app::subagents::BranchMaterialVerifier::finish)
                .is_err()
        );
    }
}
