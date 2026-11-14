#![allow(clippy::unwrap_used)]
use super::*;
const PLAN: &[u8] =
    include_bytes!("../../../../docs/development/subagent-format-vectors/plan.json");

fn golden<T: SubagentRecord>(bytes: &[u8], identity: &str) -> T {
    let value = T::decode(bytes).unwrap();
    assert_eq!(value.canonical().unwrap(), bytes);
    assert_eq!(crate::hex(value.identity().unwrap().as_bytes()), identity);
    let mut extra = bytes.to_vec();
    extra.push(b'\n');
    assert!(T::decode(&extra).is_err());
    value
}

#[test]
fn source_type_plan_reservation_checkpoint_and_result_match_approved_goldens() {
    let page = golden::<SubagentSourcePageV1>(
        include_bytes!("../../../../docs/development/subagent-format-vectors/source-page.json"),
        "6e02cf7e171a659d0849cbe050ce5635de4055c59228c05a18abac83935b1485",
    );
    let set = golden::<SubagentSourceSetV1>(
        include_bytes!("../../../../docs/development/subagent-format-vectors/source-set.json"),
        "c2fe6a787eeaaaf6e311170810e1266b55d03c03e34aafb847cbed5f803f60f0",
    );
    set.verify_pages(&[page]).unwrap();
    let kind = golden::<SubagentTypeSnapshotV1>(
        include_bytes!("../../../../docs/development/subagent-format-vectors/type-snapshot.json"),
        "34a4e7ab46587abd9c9e652db9771e4a69b0b0916cf12056e74c0682d16d9f06",
    );
    let expected_kind =
        SubagentTypeSnapshotV1::new(&crate::CaseId::parse(kind.case_id()).unwrap(), "triage")
            .unwrap();
    assert_eq!(
        kind.canonical().unwrap(),
        expected_kind.canonical().unwrap()
    );
    let plan = golden::<SubagentPlanV1>(
        PLAN,
        "785e58b663a937570721dd7c4f1d2cf1f05d1361eae6970f666b64ab462fc48e",
    );
    assert!(plan.requires_signed_consent().unwrap());
    let approval = SubagentPlanApprovalV1::decode(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/plan-approval.json"
    ))
    .unwrap();
    assert!(approval.matches(&plan).unwrap());
    assert_eq!(
        SubagentPlanApprovalV1::new(&plan, SubagentPlanDecision::Approve)
            .unwrap()
            .canonical()
            .unwrap(),
        approval.canonical().unwrap()
    );
    let reservation = golden::<SubagentReservationV1>(
        include_bytes!("../../../../docs/development/subagent-format-vectors/reservation.json"),
        "29e4f1a7c131cf4b8ddb3b94dffa024c5010859b595923e941f8fe9b48aee27f",
    );
    reservation.validate_against(&plan).unwrap();
    for raw in [
        include_bytes!("../../../../docs/development/subagent-format-vectors/preview-hold.json")
            .as_slice(),
        include_bytes!(
            "../../../../docs/development/subagent-format-vectors/tool-reservation.json"
        )
        .as_slice(),
        include_bytes!("../../../../docs/development/subagent-format-vectors/tool-settlement.json")
            .as_slice(),
    ] {
        SubagentReservationV1::decode(raw)
            .unwrap()
            .validate_against(&plan)
            .unwrap();
    }
    golden::<SubagentCheckpointV1>(
        include_bytes!(
            "../../../../docs/development/subagent-format-vectors/checkpoint-proposal.json"
        ),
        "83404dcf4aa7e58cba44042512c50739abe878ef760607d4b1526c05203a19e8",
    );
    golden::<SubagentCheckpointV1>(
        include_bytes!(
            "../../../../docs/development/subagent-format-vectors/checkpoint-final.json"
        ),
        "bc720e9b3aa2e9fb9e94a0fc4de763d798d50934dbdbd43ca097d5de94f6b066",
    );
    golden::<SubagentResultV1>(
        include_bytes!("../../../../docs/development/subagent-format-vectors/result.json"),
        "56db0c18702699c336eece54560eefa3decc9ed8119510c6bcb1496a53542c02",
    );
}

#[test]
fn whole_plan_threshold_matches_all_boundaries_and_rejects_invalid_policy_ranges() {
    let rows: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/threshold-cases.json"
    ))
    .unwrap();
    for row in rows {
        let resource = |token: &str, call: &str| SubagentResources {
            tokens: row[token].as_u64().unwrap(),
            calls: row[call].as_u64().unwrap(),
            ..SubagentResources::default()
        };
        let reserve = resource("tokens", "calls");
        let remaining = resource("remaining_tokens", "remaining_calls");
        assert_eq!(reserve.within(remaining), row["fits"].as_bool().unwrap());
        let actual = reserve.requires_signed_consent(remaining);
        if !row["policy_valid"].as_bool().unwrap() || !row["fits"].as_bool().unwrap() {
            assert!(actual.is_err());
        } else {
            assert_eq!(actual.unwrap(), row["signed_consent"].as_bool().unwrap());
        }
        if row["signed_consent"].is_boolean() {
            assert_eq!(
                u128::from(reserve.tokens) * 4 > u128::from(remaining.tokens)
                    || u128::from(reserve.calls) * 4 > u128::from(remaining.calls),
                row["signed_consent"].as_bool().unwrap()
            );
        }
    }
    let reserve = SubagentResources {
        tokens: 250_000,
        calls: 25,
        ..SubagentResources::default()
    };
    assert!(
        !reserve
            .requires_signed_consent(SubagentResources {
                tokens: 1_000_000,
                calls: 100,
                ..SubagentResources::default()
            })
            .unwrap()
    );
    assert!(
        reserve
            .requires_signed_consent(SubagentResources {
                tokens: 999_999,
                calls: 100,
                ..SubagentResources::default()
            })
            .unwrap()
    );
}

#[test]
fn aggregate_ids_accounting_and_source_order_cannot_be_rewritten() {
    let mut plan = SubagentPlanV1::decode(PLAN).unwrap();
    plan.tasks[0].budget.tokens += 1;
    assert!(plan.validate().is_err());
    let mut plan = SubagentPlanV1::decode(PLAN).unwrap();
    plan.remaining.tokens += 1;
    assert!(plan.validate().is_err());
    let mut plan = SubagentPlanV1::decode(PLAN).unwrap();
    plan.tasks[0].deadline_at += 1;
    assert!(plan.validate().is_err());
    let mut plan = SubagentPlanV1::decode(PLAN).unwrap();
    plan.tasks[0].nonce.clone_from(&plan.turn_id);
    assert!(plan.validate().is_err());
    let case = crate::CaseId::parse(&plan.case_id).unwrap();
    let a = SubagentDigest::from_bytes([1; 32]);
    let b = SubagentDigest::from_bytes([2; 32]);
    assert!(SubagentSourcePageV1::new(&case, 0, vec![b, a]).is_err());
    assert!(SubagentSourcePageV1::new(&case, 0, vec![a, a]).is_err());
    let first = SubagentSourcePageV1::new(&case, 0, vec![b]).unwrap();
    let second = SubagentSourcePageV1::new(&case, 1, vec![a]).unwrap();
    let set = SubagentSourceSetV1::new(
        &case,
        2,
        vec![first.identity().unwrap(), second.identity().unwrap()],
    )
    .unwrap();
    assert!(set.verify_pages(&[first, second]).is_err());
    assert!(SubagentTypeSnapshotV1::new(&case, "custom-type").is_err());
}

#[test]
fn canonical_reader_rejects_duplicate_unknown_oversized_and_noncanonical_fields() {
    for raw in [
        String::from_utf8(PLAN.to_vec()).unwrap().replacen(
            "\"format_version\":1",
            "\"format_version\":1,\"format_version\":1",
            1,
        ),
        String::from_utf8(PLAN.to_vec()).unwrap().replacen(
            "\"format_version\":1",
            "\"format_version\":1,\"unknown\":0",
            1,
        ),
        String::from_utf8(PLAN.to_vec()).unwrap().replacen(
            "\"format_version\":1",
            "\"format_version\":2",
            1,
        ),
    ] {
        assert!(SubagentPlanV1::decode(raw.as_bytes()).is_err());
    }
    assert!(SubagentPlanV1::decode(&vec![b' '; 256 * 1024 + 1]).is_err());
    assert!(SubagentDigest::parse(&"A".repeat(64)).is_err());
    assert!(SubagentDigest::parse(&"0".repeat(62)).is_err());
}
