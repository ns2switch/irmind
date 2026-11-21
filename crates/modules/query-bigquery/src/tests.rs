use super::*;
use futures_util::TryStreamExt as _;
use irmind_testkit::{MockResponse, MockServer};
use serde_json::Value;

fn compiled_fixture() -> (Value, SourceQueryLimits, Value) {
    let plan: Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/source-query-format-vectors/plan.json"
    ))
    .unwrap();
    let mut limits = plan["limits"].clone();
    limits["scan_bytes"] = json!(64 * 1024 * 1024);
    let source = json!({
        "id":"gcp-lab","module":"query-bigquery","module_version":"1",
        "dataset":"cloud-audit-logs","owner":"synthetic-project","location":"EU",
        "table":"audit.cloudaudit_googleapis_com_activity",
        "partitions":[{"name":"layout","type":"text","value":"timestamp-partitioned"}]
    });
    let mut query = plan["query"].clone();
    query["source"] = json!("gcp-lab");
    query["dataset"] = json!("cloud-audit-logs");
    query["fields"] = json!(["@timestamp", "event.action"]);
    query["filters"][0]["value"] = json!("x' OR '1'='1");
    (source, serde_json::from_value(limits).unwrap(), query)
}

fn executor(source: Value, limits: SourceQueryLimits) -> BigQuery {
    BigQuery::new(
        serde_json::from_value(source).unwrap(),
        limits,
        "synthetic-bearer".into(),
    )
    .unwrap()
}

#[tokio::test]
async fn capped_jobs_reconcile_by_id_and_keep_earlier_pages_on_error() {
    let (source, limits, query) = compiled_fixture();
    let mut executor = executor(source, limits);
    let query = serde_json::from_value(query).unwrap();
    let compiled = executor.compile(&executor.source, &query).unwrap();
    let job = protocol::job_id(&"a".repeat(64)).unwrap();
    let reference = json!({"jobId":job,"projectId":"synthetic-project","location":"EU"});
    let configuration = json!({"query":executor.statement(&compiled).unwrap()});
    let observed = json!({"jobReference":reference,"configuration":configuration,
        "status":{"state":"DONE","errors":[{"reason":"partial"}]},
        "statistics":{"query":{"totalBytesProcessed":"128","totalBytesBilled":"10485760"}}});
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
    let preview = executor.dry_run(&compiled, &cancel).await.unwrap();
    assert_eq!(preview.billed_bytes, 10_485_760);
    assert!(!preview.reliable);
    assert!(!executor.insert(&compiled, &job, &cancel).await.unwrap());
    let status = executor.observe(&compiled, &job, &cancel).await.unwrap();
    assert!(matches!(status.status, QueryExecutionStatus::Partial));
    assert_eq!(status.usage.scanned_bytes, Some(128));
    assert_eq!(status.usage.billed_bytes, Some(10_485_760));
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
        "67108864"
    );
    assert_eq!(submit["jobReference"], reference);
    assert_eq!(
        submit["configuration"]["query"]["queryParameters"][0]["parameterValue"]["value"],
        "2026-11-16T00:00:00.000000Z"
    );
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
    assert!(
        calls[4]
            .target
            .contains("formatOptions.useInt64Timestamp=true")
    );
    assert!(calls[5].target.contains("/cancel?location=EU"));
}

#[tokio::test]
async fn rejected_dry_run_limits_and_cancelled_requests_do_not_submit() {
    let (source, limits, query) = compiled_fixture();
    let mut executor = executor(source, limits);
    let query = serde_json::from_value(query).unwrap();
    let compiled = executor.compile(&executor.source, &query).unwrap();
    let server = MockServer::start(vec![MockResponse::json(
        r#"{"configuration":{"dryRun":true},"statistics":{"query":{"totalBytesProcessed":"67108865"}}}"#,
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

#[tokio::test]
async fn real_sink_table_names_and_both_layouts_are_explicit_on_the_wire() {
    let fixtures: Value =
        serde_json::from_str(include_str!("../fixtures/logging-sink-tables.json")).unwrap();
    for fixture in fixtures["sources"].as_array().unwrap() {
        let (mut source, limits, query) = compiled_fixture();
        let base = fixture["base"].as_str().unwrap();
        let table = fixture["table"]["tableReference"]["tableId"]
            .as_str()
            .unwrap();
        source["table"] = json!(format!("audit.{base}"));
        source["partitions"][0]["value"] = fixture["layout"].clone();
        let mut executor = executor(source, limits);
        let query = serde_json::from_value(query).unwrap();
        let compiled = executor.compile(&executor.source, &query).unwrap();
        let simulated = json!({"configuration":{"dryRun":true},"statistics":{"query":{
            "totalBytesProcessed":"1024","referencedTables":[fixture["table"]["tableReference"]],"schema":fixtures["schema"]
        }}});
        let server = MockServer::start(vec![MockResponse::json(&simulated.to_string())]).unwrap();
        executor.endpoint = reqwest::Url::parse(server.origin()).unwrap();
        executor
            .dry_run(&compiled, &CancellationToken::new())
            .await
            .unwrap();
        let calls = server.finish().unwrap();
        let body: Value = serde_json::from_slice(&calls[0].body).unwrap();
        let sql = body["configuration"]["query"]["query"].as_str().unwrap();
        assert!(sql.contains("timestamp >= @from AND timestamp < @to"));
        assert!(!sql.contains("_PARTITIONDATE"));
        if fixture["layout"] == "date-sharded" {
            assert_eq!(table, format!("{base}_20261116"));
            assert!(sql.contains(&format!("`synthetic-project.audit.{base}_*`")));
            assert!(sql.contains("_TABLE_SUFFIX BETWEEN @first_day AND @last_day"));
            assert!(sql.contains("REGEXP_CONTAINS(_TABLE_SUFFIX, r'^[0-9]{8}$')"));
            for (index, day) in [(3, "20261116"), (4, "20261117")] {
                assert_eq!(
                    body["configuration"]["query"]["queryParameters"][index]["parameterValue"]["value"],
                    day
                );
            }
        } else {
            assert_eq!(table, base);
            assert_eq!(fixture["table"]["timePartitioning"]["field"], "timestamp");
            assert!(sql.contains(&format!("`synthetic-project.audit.{base}`")));
            assert!(!sql.contains("_TABLE_SUFFIX"));
        }
    }
}

#[test]
fn missing_or_unknown_source_layout_and_unapproved_table_are_rejected() {
    let (source, _, _) = compiled_fixture();
    for partitions in [
        json!([]),
        json!([{"name":"layout","type":"text","value":"auto"}]),
    ] {
        let mut changed = source.clone();
        changed["partitions"] = partitions;
        let resolved = serde_json::from_value(changed).unwrap();
        assert!(compiler::table_layout(&resolved).is_err());
    }
    let mut changed = source;
    changed["table"] = json!("audit.cloudaudit_googleapis_com_activity_20261116");
    assert!(compiler::table_layout(&serde_json::from_value(changed).unwrap()).is_err());
}
