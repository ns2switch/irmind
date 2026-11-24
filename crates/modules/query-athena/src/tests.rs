use super::*;
use futures_util::TryStreamExt as _;
use irmind_testkit::{MockResponse, MockServer};
use serde_json::Value;

const PLAN: &[u8] =
    include_bytes!("../../../../docs/development/source-query-format-vectors/plan.json");
const JOB: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const CUTOFF: &str = r#"{"WorkGroup":{"Name":"irmind_lab","State":"ENABLED","Configuration":{"EnforceWorkGroupConfiguration":true,"BytesScannedCutoffPerQuery":11534335,"EngineVersion":{"EffectiveEngineVersion":"Athena engine version 3"}}}}"#;

fn fixture(server: &MockServer) -> (Athena, Value) {
    let mut plan: Value = serde_json::from_slice(PLAN).unwrap();
    plan["query"]["fields"] = json!(["@timestamp", "event.action", "source.ip"]);
    let source =
        ResolvedQuerySourceV1::decode(&canonical_query_json(&plan["source"]).unwrap()).unwrap();
    plan["limits"]["scan_bytes"] = json!(11 * 1024 * 1024);
    let limits = serde_json::from_value(plan["limits"].clone()).unwrap();
    let mut executor = Athena::new(
        source,
        limits,
        "irmind_lab",
        Credentials::new("AKIDSYNTHETIC", "synthetic-secret", None, None, "synthetic"),
        true,
        Arc::new(irmind_infra::SystemClock),
    )
    .unwrap();
    executor.endpoint = reqwest::Url::parse(server.origin()).unwrap();
    (executor, plan)
}

#[tokio::test]
async fn protocol_keeps_the_same_submission_key_and_preserves_partial_results() {
    let mut first_page: Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/source-query-format-vectors/page-0.json",
    ))
    .unwrap();
    first_page["NextToken"] = json!("next/+opaque");
    let accepted = json!({"QueryExecutionId":JOB}).to_string();
    let status = json!({"QueryExecution":{"QueryExecutionId":JOB,"WorkGroup":"irmind_lab",
        "Status":{"State":"SUCCEEDED"},"Statistics":{"DataScannedInBytes":4096}}})
    .to_string();
    let server = MockServer::start(vec![
        MockResponse::json(CUTOFF),
        MockResponse::status(502),
        MockResponse::json(&accepted),
        MockResponse::json(&status),
        MockResponse::json(&first_page.to_string()),
        MockResponse::status(500),
        MockResponse::json("{}"),
    ])
    .unwrap();
    let (executor, plan) = fixture(&server);
    let cancel = CancellationToken::new();
    let query = SourceQueryV1::decode(&canonical_query_json(&plan["query"]).unwrap()).unwrap();
    let compiled = executor.compile(&executor.source, &query).unwrap();
    let token = "a".repeat(64);
    assert_eq!(
        executor.scan_cutoff(&cancel).await.unwrap(),
        11 * 1024 * 1024
    );
    assert!(executor.start(&compiled, &token, &cancel).await.is_err());
    assert_eq!(
        executor.start(&compiled, &token, &cancel).await.unwrap(),
        JOB
    );
    assert_eq!(
        executor
            .observe(JOB, &cancel)
            .await
            .unwrap()
            .usage
            .scanned_bytes,
        Some(4096)
    );
    let page = executor.fetch_page(JOB, None, &cancel).await.unwrap();
    assert_eq!(protocol::billable_bytes(4096), Some(10 * 1024 * 1024));
    assert_eq!(page.next_token.as_deref(), Some("next/+opaque"));
    let bytes = page.chunks.try_concat().await.unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), first_page);
    assert!(
        executor
            .fetch_page(JOB, page.next_token.as_deref(), &cancel)
            .await
            .is_err()
    );
    assert!(matches!(
        executor.stop(JOB, &cancel).await.unwrap(),
        CancelObservationV1::Requested
    ));
    let calls = server.finish().unwrap();
    assert_eq!(calls[1].body, calls[2].body);
    assert!(
        calls
            .iter()
            .all(|call| call.headers["authorization"].starts_with("AWS4-HMAC-SHA256"))
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&calls[5].body).unwrap()["NextToken"],
        "next/+opaque"
    );
    assert_eq!(
        calls[6].headers["x-amz-target"],
        "AmazonAthena.StopQueryExecution"
    );
}

#[tokio::test]
async fn literals_stay_outside_sql_and_cancelled_requests_make_no_connection() {
    let server = MockServer::start(vec![]).unwrap();
    let (executor, mut plan) = fixture(&server);
    plan["query"]["filters"][0]["value"] = json!("x' OR '1'='1");
    let query = SourceQueryV1::decode(&canonical_query_json(&plan["query"]).unwrap()).unwrap();
    let compiled = executor.compile(&executor.source, &query).unwrap();
    assert!(!compiled.text().contains("OR '1'"));
    assert!(
        compiled
            .bindings()
            .iter()
            .any(|binding| binding.value == "x' OR '1'='1")
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        executor.scan_cutoff(&cancel).await,
        Err(AppError::Cancelled)
    ));
    assert!(server.finish().unwrap().is_empty());
}

#[tokio::test]
async fn source_ip_and_account_filters_bind_without_widening_the_adopted_scope() {
    let server = MockServer::start(vec![MockResponse::json(
        &json!({"QueryExecutionId":JOB}).to_string(),
    )])
    .unwrap();
    let (executor, mut plan) = fixture(&server);
    plan["query"]["filters"] = json!([
        {"field":"cloud.account.id","op":"eq","value":"111122223333"},
        {"field":"source.ip","op":"eq","value":"2001:db8::9"}
    ]);
    let query = serde_json::from_value(plan["query"].clone()).unwrap();
    let compiled = executor.compile(&executor.source, &query).unwrap();
    assert!(
        compiled
            .text()
            .contains("TRY_CAST(sourceipaddress AS IPADDRESS) = CAST(? AS IPADDRESS)")
    );
    assert_eq!(compiled.text().matches("recipientaccountid = ?").count(), 2);
    assert!(!compiled.text().contains("2001:db8::9"));
    assert!(!compiled.text().contains("111122223333"));
    assert_eq!(compiled.bindings()[4].kind, "ip");
    assert!(compiled.text().contains("strpos(sourceipaddress, ':') > 0"));
    let mut ipv4_query = plan["query"].clone();
    ipv4_query["filters"][1]["value"] = json!("203.0.113.9");
    let ipv4 = executor
        .compile(
            &executor.source,
            &serde_json::from_value(ipv4_query).unwrap(),
        )
        .unwrap();
    assert!(ipv4.text().contains("strpos(sourceipaddress, ':') = 0"));
    assert_eq!(ipv4.bindings()[4].value, "203.0.113.9");
    executor
        .start(&compiled, &"a".repeat(64), &CancellationToken::new())
        .await
        .unwrap();
    let calls = server.finish().unwrap();
    let body: Value = serde_json::from_slice(&calls[0].body).unwrap();
    assert_eq!(body["ExecutionParameters"][3], "'111122223333'");
    assert_eq!(body["ExecutionParameters"][4], "'2001:db8::9'");

    plan["query"]["filters"][0]["value"] = json!("999999999999");
    let other_account = serde_json::from_value(plan["query"].clone()).unwrap();
    assert!(matches!(
        executor.compile(&executor.source, &other_account),
        Err(AppError::SourceQuery(SourceQueryError::Scope))
    ));
    plan["query"]["filters"][1]["value"] = json!("2001:db8::9') OR ('x'='x");
    assert!(serde_json::from_value::<SourceQueryV1>(plan["query"].clone()).is_err());
}

#[tokio::test]
async fn usage_and_workgroup_cutoff_use_billed_units() {
    let observations = |state: &str, scanned: Option<u64>| {
        MockResponse::json(
            &json!({"QueryExecution":{"QueryExecutionId":JOB,"WorkGroup":"irmind_lab",
            "Status":{"State":state},"Statistics":{"DataScannedInBytes":scanned}}})
            .to_string(),
        )
    };
    let server = MockServer::start(vec![
        MockResponse::json(CUTOFF),
        observations("SUCCEEDED", Some(4096)),
        observations("CANCELLED", Some(10 * (1 << 20) + 1)),
        observations("FAILED", Some(4096)),
        observations("SUCCEEDED", None),
    ])
    .unwrap();
    let (mut executor, _) = fixture(&server);
    executor.limits.scan_bytes = Some(11 * (1 << 20) - 1);
    let cancel = CancellationToken::new();
    assert!(executor.scan_cutoff(&cancel).await.is_err());
    for (raw, billed) in [
        (Some(4096), Some(10 * (1 << 20))),
        (Some(10 * (1 << 20) + 1), Some(11 * (1 << 20))),
        (Some(4096), Some(0)),
        (None, None),
    ] {
        let observation = executor.observe(JOB, &cancel).await.unwrap();
        assert_eq!(observation.usage.scanned_bytes, raw);
        assert_eq!(observation.usage.billed_bytes, billed);
    }
    assert_eq!(server.finish().unwrap().len(), 5);
    assert_eq!(protocol::billable_bytes(u64::MAX), None);
}

#[path = "../../../testkit/provider_tests/source_query_v10.rs"]
mod case_contract;

#[test]
fn real_clock_preflight_and_exact_v9_citation() {
    let mut page: Value = serde_json::from_slice(include_bytes!(
        "../../../../fuzz/seeds/query_page_athena/page.json"
    ))
    .unwrap();
    let rows = page["ResultSet"]["Rows"].as_array_mut().unwrap();
    rows[0]["Data"][2]["VarCharValue"] = json!(case_contract::FIRST);
    rows[0]["Data"][0]["VarCharValue"] = json!(case_contract::AT);
    rows[0]["Data"][3]["VarCharValue"] = json!("111122223333");
    let mut second = rows[0].clone();
    second["Data"][2]["VarCharValue"] = json!(case_contract::CITED);
    rows.push(second);
    let status = json!({"QueryExecution":{"QueryExecutionId":JOB,"WorkGroup":"irmind_lab",
        "Status":{"State":"SUCCEEDED"},"Statistics":{"DataScannedInBytes":4096}}});
    let server = MockServer::start(vec![
        MockResponse::json(CUTOFF),
        MockResponse::json(CUTOFF),
        MockResponse::json(&json!({"QueryExecutionId":JOB}).to_string()),
        MockResponse::json(&status.to_string()),
        MockResponse::json(&page.to_string()),
    ])
    .unwrap();
    let (mut executor, plan) = fixture(&server);
    let clock = Arc::new(case_contract::ObservedClock::default());
    executor.clock = clock.clone();
    let fixture = case_contract::Fixture {
        source: executor.source.clone(),
        limits: executor.limits.clone(),
        query: plan["query"].clone(),
        billed_bytes: 10 << 20,
        citation_field: "eventID",
    };
    case_contract::acquire_and_export(
        &fixture,
        executor,
        AthenaCaptureDecoder,
        irmind_mod_mapping_cloudtrail::CloudTrailMapping::for_capture().unwrap(),
        clock.as_ref(),
    );
    let calls = server.finish().unwrap();
    assert_eq!(
        calls[4].headers["x-amz-target"],
        "AmazonAthena.GetQueryResults"
    );
}
