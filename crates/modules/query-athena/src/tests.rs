use super::*;
use futures_util::TryStreamExt as _;
use irmind_testkit::{MockResponse, MockServer};
use serde_json::Value;

const PLAN: &[u8] =
    include_bytes!("../../../../docs/development/source-query-format-vectors/plan.json");
const JOB: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const CUTOFF: &str = r#"{"WorkGroup":{"Name":"irmind_lab","State":"ENABLED","Configuration":{"EnforceWorkGroupConfiguration":true,"BytesScannedCutoffPerQuery":1000000}}}"#;

fn fixture(server: &MockServer) -> (Athena, Value) {
    let mut plan: Value = serde_json::from_slice(PLAN).unwrap();
    plan["query"]["fields"] = json!(["@timestamp", "event.action", "source.ip"]);
    let source =
        ResolvedQuerySourceV1::decode(&canonical_query_json(&plan["source"]).unwrap()).unwrap();
    let limits = serde_json::from_value(plan["limits"].clone()).unwrap();
    let mut executor = Athena::new(
        source,
        limits,
        "irmind_lab",
        Credentials::new("AKIDSYNTHETIC", "synthetic-secret", None, None, "synthetic"),
        true,
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
    assert_eq!(executor.scan_cutoff(&cancel).await.unwrap(), 1_000_000);
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
