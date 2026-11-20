#![allow(clippy::unwrap_used)]
use super::*;
use irmind_domain::{CaseId, CaseScope};

const PLAN: &[u8] =
    include_bytes!("../../../../docs/development/source-query-format-vectors/plan.json");
const APPROVAL: &[u8] =
    include_bytes!("../../../../docs/development/source-query-format-vectors/approval.json");
const RESERVATION: &[u8] =
    include_bytes!("../../../../docs/development/source-query-format-vectors/reservation.json");
const IDENTITIES: &[u8] =
    include_bytes!("../../../../docs/development/source-query-format-vectors/identities.json");
const SCOPE: &str = "v1;sources=aws-lab;accounts=111122223333;hosts=;from=2026-11-01T00:00:00Z;to=2026-12-01T00:00:00Z";

fn case() -> CaseId {
    CaseId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}

fn allocation() -> SourceQueryAllocationV1 {
    SourceQueryAllocationV1 {
        enabled: true,
        analytics_allowed: false,
        scan_bytes: Some(1_000_000),
        retained_rows: 100_000,
        retained_bytes: 100_000_000,
    }
}

fn records() -> (
    SourceQueryPlanV1,
    SourceQueryApprovalV1,
    SourceQueryReservationV1,
) {
    (
        SourceQueryPlanV1::decode(PLAN).unwrap(),
        SourceQueryApprovalV1::decode(APPROVAL).unwrap(),
        SourceQueryReservationV1::decode(RESERVATION).unwrap(),
    )
}

#[test]
fn approved_receipts_match_the_exact_canonical_vectors() {
    let (plan, approval, reservation) = records();
    let identities: serde_json::Value = serde_json::from_slice(IDENTITIES).unwrap();
    assert_eq!(plan.content_id().unwrap(), identities["plan"]);
    assert_eq!(approval.content_id().unwrap(), identities["approval"]);
    assert_eq!(reservation.content_id().unwrap(), identities["reservation"]);
    assert_eq!(canonical_query_json(&plan).unwrap(), PLAN);
    assert_eq!(canonical_query_json(&approval).unwrap(), APPROVAL);
    assert_eq!(canonical_query_json(&reservation).unwrap(), RESERVATION);
}

#[test]
fn execution_leases_bind_the_exact_source_phase_and_job() {
    let wire: serde_json::Value = serde_json::from_slice(PLAN).unwrap();
    let plan = SourceQueryPlanV1::decode(PLAN)
        .unwrap()
        .content_id()
        .unwrap();
    let job = QueryExecutionRef::new(&plan, 1, "native-job-a").unwrap();
    let another = QueryExecutionRef::new(&plan, 1, "native-job-b").unwrap();
    let source: ResolvedQuerySourceV1 = serde_json::from_value(wire["source"].clone()).unwrap();
    let lease = AdmittedSourceQuery {
        case_id: case(),
        plan,
        reservation: SourceQueryReservationV1::decode(RESERVATION)
            .unwrap()
            .content_id()
            .unwrap(),
        source,
        compiled: serde_json::from_value(wire["compiled"].clone()).unwrap(),
        limits: serde_json::from_value(wire["limits"].clone()).unwrap(),
        execution_key: "intent-a".into(),
        phase: SourceQueryLeasePhase::Fetch,
        execution: Some(job.clone()),
    };
    let check = |source, phase, execution| lease.check("query-athena", source, phase, execution);
    assert_eq!(
        check("aws-lab", SourceQueryLeasePhase::Fetch, Some(&job)),
        Ok(())
    );
    for (source, phase, execution) in [
        ("other-lab", SourceQueryLeasePhase::Fetch, Some(&job)),
        ("aws-lab", SourceQueryLeasePhase::Fetch, Some(&another)),
        ("aws-lab", SourceQueryLeasePhase::Fetch, None),
        ("aws-lab", SourceQueryLeasePhase::Cancel, Some(&job)),
    ] {
        assert_eq!(
            check(source, phase, execution),
            Err(SourceQueryError::Scope)
        );
    }
}

#[test]
fn compiler_refuses_unregistered_datasets_result_kinds_and_predicates() {
    let plan: serde_json::Value = serde_json::from_slice(PLAN).unwrap();
    let source: ResolvedQuerySourceV1 = serde_json::from_value(plan["source"].clone()).unwrap();
    let query: SourceQueryV1 = serde_json::from_value(plan["query"].clone()).unwrap();
    let limits: SourceQueryLimits = serde_json::from_value(plan["limits"].clone()).unwrap();
    let mut module = SourceQueryModuleV1 {
        id: source.module().into(),
        version: source.module_version().into(),
        datasets: vec![query.dataset().into()],
        fields: query
            .fields()
            .iter()
            .cloned()
            .chain(query.filters().iter().map(|filter| filter.field.clone()))
            .collect(),
        operators: vec![QueryOperator::Eq],
        result_kinds: vec![QueryResultKind::Events],
        accounting: QueryAccounting::ScanPriced,
        recoverable_submit: true,
        cancellation: true,
        api_version: "v1".into(),
    };
    assert_eq!(
        check_query_capabilities(&query, &source, &module, &limits),
        Ok(())
    );
    let mut aggregate = plan["query"].clone();
    aggregate["result"] = "count".into();
    let aggregate = serde_json::from_value(aggregate).unwrap();
    assert_eq!(
        check_query_capabilities(&aggregate, &source, &module, &limits),
        Err(SourceQueryError::Unsupported)
    );
    module.operators.clear();
    assert_eq!(
        check_query_capabilities(&query, &source, &module, &limits),
        Err(SourceQueryError::Unsupported)
    );
    module.operators.push(QueryOperator::Eq);
    module.datasets[0] = "other-dataset".into();
    assert_eq!(
        check_query_capabilities(&query, &source, &module, &limits),
        Err(SourceQueryError::Unsupported)
    );
}

#[test]
fn scope_approval_and_allocation_revision_are_required_for_a_hold() {
    let (plan, approval, reservation) = records();
    let scope = CaseScope::parse(SCOPE).unwrap();
    let other_scope = CaseScope::parse(&SCOPE.replace("111122223333", "444455556666")).unwrap();
    let mut broker =
        SourceQueryBroker::new(case(), SourceQueryAllocationV1::default(), allocation()).unwrap();
    assert_eq!(
        broker
            .reserve(
                &plan,
                &reservation,
                Some(&approval),
                &scope,
                &scope,
                500_000,
                false,
                5,
                None
            )
            .err(),
        Some(SourceQueryError::Disabled)
    );
    assert!(broker.change_allocation(2, allocation()).is_err());
    broker.change_allocation(1, allocation()).unwrap();
    assert_eq!(
        broker
            .reserve(
                &plan,
                &reservation,
                None,
                &scope,
                &scope,
                500_000,
                false,
                5,
                None
            )
            .err(),
        Some(SourceQueryError::Approval)
    );
    assert_eq!(
        broker
            .reserve(
                &plan,
                &reservation,
                Some(&approval),
                &scope,
                &other_scope,
                500_000,
                false,
                5,
                None
            )
            .err(),
        Some(SourceQueryError::Scope)
    );
    let mut changed: serde_json::Value = serde_json::from_slice(PLAN).unwrap();
    changed["query"]["limit"] = 99_999.into();
    let changed = SourceQueryPlanV1::decode(&canonical_query_json(&changed).unwrap()).unwrap();
    assert_eq!(
        broker
            .reserve(
                &changed,
                &reservation,
                Some(&approval),
                &scope,
                &scope,
                500_000,
                false,
                5,
                None
            )
            .err(),
        Some(SourceQueryError::Approval)
    );
    assert_eq!(broker.held(), SourceQueryResources::default());
}

#[test]
fn holds_survive_unknown_usage_and_known_overruns_are_charged_once() {
    let (plan, approval, reservation) = records();
    let scope = CaseScope::parse(SCOPE).unwrap();
    let mut broker = SourceQueryBroker::new(case(), allocation(), allocation()).unwrap();
    broker.change_allocation(1, allocation()).unwrap();
    let hold = broker
        .reserve(
            &plan,
            &reservation,
            Some(&approval),
            &scope,
            &scope,
            500_000,
            false,
            5,
            None,
        )
        .unwrap();
    assert_eq!(broker.held(), hold.resources());
    assert!(
        broker
            .change_allocation(2, SourceQueryAllocationV1::default())
            .is_err()
    );
    assert_eq!(
        broker.settle(hold.id(), None, 0, 0),
        Err(SourceQueryError::Unresolved)
    );
    assert_eq!(broker.held(), hold.resources());
    assert_eq!(
        broker
            .reserve(
                &plan,
                &reservation,
                Some(&approval),
                &scope,
                &scope,
                500_000,
                false,
                5,
                None
            )
            .err(),
        Some(SourceQueryError::Unresolved)
    );
    assert!(broker.settle(hold.id(), Some(10), 2, 100_000_001).is_err());
    broker.settle(hold.id(), Some(1_000_001), 2, 2391).unwrap();
    assert_eq!(broker.used().scan_bytes, 1_000_001);
    assert_eq!(broker.held(), SourceQueryResources::default());
    assert_eq!(
        broker.settle(hold.id(), Some(0), 0, 0),
        Err(SourceQueryError::AlreadySettled)
    );
    assert!(broker.change_allocation(2, allocation()).is_err());
}

#[test]
fn child_and_noncanonical_receipts_are_rejected() {
    let mut value: serde_json::Value = serde_json::from_slice(RESERVATION).unwrap();
    value["task_id"] = "22222222-2222-4222-8222-222222222222".into();
    assert_eq!(
        SourceQueryReservationV1::decode(&canonical_query_json(&value).unwrap()).err(),
        Some(SourceQueryError::Subagent)
    );
    let mut changed = PLAN.to_vec();
    changed.push(b'\n');
    assert_eq!(
        SourceQueryPlanV1::decode(&changed).err(),
        Some(SourceQueryError::Invalid)
    );
}

#[test]
fn source_query_budget_replay_binds_the_case_analyst_and_revision() {
    let raw =
        include_bytes!("../../../../docs/development/source-query-format-vectors/budget.json");
    let identities: serde_json::Value = serde_json::from_slice(IDENTITIES).unwrap();
    let record = SourceQueryBudgetV1::decode(raw).unwrap();
    assert_eq!(record.content_id().unwrap(), identities["budget"]);
    let encoded: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/source-query-format-vectors/signed-record-chain.json"
    ))
    .unwrap();
    let first: crate::SignedEntry = serde_json::from_value(encoded[0].clone()).unwrap();
    let budget: crate::SignedEntry = serde_json::from_value(encoded[1].clone()).unwrap();
    let mut replay = BudgetReplay::new(&first, SourceQueryAllocationV1::default());
    let mut foreign = budget.clone();
    foreign.public_key[0] ^= 1;
    assert!(replay.accept(&foreign).is_err());
    replay.accept(&budget).unwrap();
    assert_eq!(replay.current().0, 1);
    assert_eq!(replay.current().1.scan_bytes, Some(10_000_000));
    assert!(replay.accept(&budget).is_err());
}

#[test]
fn pagination_binds_plan_attempt_and_job_and_rejects_token_cycles() {
    let plan = "01".repeat(32);
    let execution = QueryExecutionRef::new(&plan, 1, "synthetic-job").unwrap();
    let other_attempt = QueryExecutionRef::new(&plan, 2, "synthetic-job").unwrap();
    let other_plan = QueryExecutionRef::new(&"02".repeat(32), 1, "synthetic-job").unwrap();
    let cursor = QueryResultCursor::first(&execution);
    assert!(cursor.check(&other_attempt).is_err());
    assert!(cursor.check(&other_plan).is_err());
    let cursor = cursor.next(&execution, "synthetic-page-a").unwrap();
    assert!(!format!("{cursor:?}").contains("synthetic-page-a"));
    let cursor = cursor.next(&execution, "synthetic-page-b").unwrap();
    assert_eq!(cursor.ordinal(), 2);
    assert!(cursor.next(&execution, "synthetic-page-a").is_err());
}
