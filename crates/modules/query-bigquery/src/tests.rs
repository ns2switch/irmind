use super::*;
use futures_util::TryStreamExt as _;
use irmind_testkit::{MockResponse, MockServer};
use serde_json::Value;

pub(super) fn compiled_fixture() -> (ResolvedQuerySourceV1, SourceQueryLimits, SourceQueryV1) {
    let plan: Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/source-query-format-vectors/plan.json"
    ))
    .unwrap();
    let source = json!({
        "id":"gcp-lab","module":"query-bigquery","module_version":"1",
        "dataset":"cloud-audit-logs","owner":"synthetic-project","location":"EU",
        "table":"audit.activity",
        "partitions":[{"name":"partition_date","type":"text","value":"2026-11-17"}]
    });
    let mut query = plan["query"].clone();
    query["source"] = json!("gcp-lab");
    query["dataset"] = json!("cloud-audit-logs");
    query["fields"] = json!(["@timestamp", "event.action"]);
    query["filters"][0]["value"] = json!("x' OR '1'='1");
    (
        ResolvedQuerySourceV1::decode(&canonical_query_json(&source).unwrap()).unwrap(),
        serde_json::from_value(plan["limits"].clone()).unwrap(),
        SourceQueryV1::decode(&canonical_query_json(&query).unwrap()).unwrap(),
    )
}

#[tokio::test]
async fn capped_jobs_reconcile_by_id_and_keep_earlier_pages_on_error() {
    let (source, limits, query) = compiled_fixture();
    let mut executor = BigQuery::new(source, limits, "synthetic-bearer".into()).unwrap();
    let compiled = executor.compile(&executor.source, &query).unwrap();
    let job = protocol::job_id(&"a".repeat(64)).unwrap();
    let reference = json!({"jobId":job,"projectId":"synthetic-project","location":"EU"});
    let configuration = json!({"query":executor.statement(&compiled).unwrap()});
    let observed = json!({"jobReference":reference,"configuration":configuration,
        "status":{"state":"DONE","errors":[{"reason":"partial"}]},
        "statistics":{"query":{"totalBytesProcessed":"128","totalBytesBilled":"256"}}});
    let page = json!({"jobReference":reference,"jobComplete":true,
        "pageToken":"opaque+/?","rows":[{"f":[{"v":"synthetic"}]}]});
    let server = MockServer::start(vec![
        MockResponse::json(r#"{"configuration":{"dryRun":true},"statistics":{"query":{"totalBytesProcessed":"128"}}}"#),
        MockResponse::status(409),
        MockResponse::json(&observed.to_string()),
        MockResponse::json(&page.to_string()),
        MockResponse::status(500),
        MockResponse::json(&json!({"job":{"jobReference":reference}}).to_string()),
    ]).unwrap();
    executor.endpoint = reqwest::Url::parse(server.origin())
        .unwrap()
        .join("bigquery/v2/")
        .unwrap();
    let cancel = CancellationToken::new();
    assert_eq!(executor.dry_run(&compiled, &cancel).await.unwrap(), 128);
    assert!(!executor.insert(&compiled, &job, &cancel).await.unwrap());
    let status = executor.observe(&compiled, &job, &cancel).await.unwrap();
    assert!(matches!(status.status, QueryExecutionStatus::Partial));
    assert_eq!(status.usage.scanned_bytes, Some(128));
    assert_eq!(status.usage.billed_bytes, Some(256));
    let first = executor.page(&job, None, &cancel).await.unwrap();
    assert_eq!(first.next_token.as_deref(), Some("opaque+/?"));
    assert_eq!(
        serde_json::from_slice::<Value>(&first.chunks.try_concat().await.unwrap()).unwrap(),
        page
    );
    assert!(
        executor
            .page(&job, first.next_token.as_deref(), &cancel)
            .await
            .is_err()
    );
    assert!(matches!(
        executor.stop(&job, &cancel).await.unwrap(),
        CancelObservationV1::Requested
    ));

    let calls = server.finish().unwrap();
    let preflight: Value = serde_json::from_slice(&calls[0].body).unwrap();
    let submit: Value = serde_json::from_slice(&calls[1].body).unwrap();
    assert_eq!(preflight["configuration"]["query"], configuration["query"]);
    assert_eq!(
        submit["configuration"]["query"]["maximumBytesBilled"],
        "1000000"
    );
    assert_eq!(submit["jobReference"], reference);
    assert!(!compiled.text().contains("OR '1'"));
    assert_eq!(
        submit["configuration"]["query"]["queryParameters"][3]["parameterValue"]["value"],
        "x' OR '1'='1"
    );
    assert!(
        calls
            .iter()
            .all(|call| call.headers["authorization"] == "Bearer synthetic-bearer")
    );
    assert!(calls[4].target.contains("pageToken=opaque%2B%2F%3F"));
    assert!(calls[5].target.contains("/cancel?location=EU"));
}

#[tokio::test]
async fn rejected_dry_run_limits_and_cancelled_requests_do_not_submit() {
    let (source, limits, query) = compiled_fixture();
    let mut executor = BigQuery::new(source, limits, "synthetic-bearer".into()).unwrap();
    let compiled = executor.compile(&executor.source, &query).unwrap();
    let server = MockServer::start(vec![MockResponse::json(
        r#"{"configuration":{"dryRun":true},"statistics":{"query":{"totalBytesProcessed":"1000001"}}}"#,
    )]).unwrap();
    executor.endpoint = reqwest::Url::parse(server.origin()).unwrap();
    let cancel = CancellationToken::new();
    assert!(executor.dry_run(&compiled, &cancel).await.is_err());
    cancel.cancel();
    assert!(matches!(
        executor
            .insert(
                &compiled,
                &protocol::job_id(&"b".repeat(64)).unwrap(),
                &cancel
            )
            .await,
        Err(AppError::Cancelled)
    ));
    assert_eq!(server.finish().unwrap().len(), 1);
}
