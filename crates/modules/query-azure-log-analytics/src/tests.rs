use super::*;
use futures_util::TryStreamExt as _;
use irmind_testkit::{MockResponse, MockServer};
use serde_json::Value;

const WORKSPACE: &str = "11111111-2222-4333-8444-555555555555";
const TOKEN: &str = r#"{"token_type":"Bearer","access_token":"synthetic-bearer"}"#;
const WORKSPACE_ARM: &str = r#"{"location":"westeurope","properties":{"customerId":"11111111-2222-4333-8444-555555555555"}}"#;
const PARTIAL: &str = include_str!(
    "../../../../docs/development/source-query-format-vectors/azure-partial-response.json"
);

fn table(plan: &str) -> MockResponse {
    MockResponse::json(
        &json!({"name":"SigninLogs","properties":{"plan":plan,
        "provisioningState":"Succeeded","retentionInDays":30}})
        .to_string(),
    )
}

fn fixture(server: &MockServer) -> (AzureLogAnalytics, CompiledSourceQueryV1) {
    let plan: Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/source-query-format-vectors/plan.json"
    ))
    .unwrap();
    let source = json!({"id":"azure-lab","module":"query-azure-log-analytics","module_version":"1",
        "dataset":"entra-signins","table":"SigninLogs","owner":WORKSPACE,"location":"westeurope",
        "partitions":[]});
    let source = ResolvedQuerySourceV1::decode(&canonical_query_json(&source).unwrap()).unwrap();
    let mut query = plan["query"].clone();
    query["source"] = json!("azure-lab");
    query["dataset"] = json!("entra-signins");
    query["fields"] = json!(["@timestamp"]);
    query["filters"] = json!([]);
    let query = SourceQueryV1::decode(&canonical_query_json(&query).unwrap()).unwrap();
    let mut limits: SourceQueryLimits = serde_json::from_value(plan["limits"].clone()).unwrap();
    limits.scan_bytes = None;
    let mut executor = AzureLogAnalytics::new(
        source,
        limits,
        "21111111-2222-4333-8444-555555555555",
        "31111111-2222-4333-8444-555555555555",
        "synthetic-secret".into(),
        "41111111-2222-4333-8444-555555555555",
        "synthetic-rg",
        "synthetic-workspace",
    )
    .unwrap();
    let base = reqwest::Url::parse(server.origin()).unwrap();
    executor.identity = base.join("oauth2/v2.0/token").unwrap();
    executor.arm = base.join("arm/").unwrap();
    executor.logs = base.join("v1/").unwrap();
    let compiled = executor.compile(&executor.source, &query).unwrap();
    (executor, compiled)
}

#[tokio::test]
async fn analytics_is_required_and_the_single_capture_keeps_provider_partial_error() {
    let server = MockServer::start(vec![
        MockResponse::json(TOKEN),
        MockResponse::json(WORKSPACE_ARM),
        table("Basic"),
        MockResponse::json(TOKEN),
        MockResponse::json(WORKSPACE_ARM),
        table("Analytics"),
        MockResponse::json(TOKEN),
        MockResponse::json(PARTIAL),
    ])
    .unwrap();
    let (executor, compiled) = fixture(&server);
    let cancel = CancellationToken::new();
    assert!(executor.analytics_plan(&cancel).await.is_err());
    assert_eq!(
        executor.analytics_plan(&cancel).await.unwrap()["plan"],
        "Analytics"
    );
    let response = executor.query(&compiled, &cancel).await.unwrap();
    let page = executor.single_page(response, "req-synthetic".into(), &cancel);
    assert!(page.next_token.is_none());
    assert_eq!(&page.chunks.try_concat().await.unwrap(), PARTIAL.as_bytes());
    let calls = server.finish().unwrap();
    assert_eq!(calls[1].headers["authorization"], "Bearer synthetic-bearer");
    assert!(
        String::from_utf8_lossy(&calls[3].body)
            .contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default")
    );
    assert!(
        String::from_utf8_lossy(&calls[6].body)
            .contains("scope=https%3A%2F%2Fapi.loganalytics.io%2F.default")
    );
    let body: Value = serde_json::from_slice(&calls[7].body).unwrap();
    assert_eq!(body["query"], compiled.text());
    assert_eq!(
        body["timespan"],
        "2026-11-16T00:00:00.000000000Z/2026-11-18T00:00:00.000000000Z"
    );
    assert_eq!(calls[7].headers["prefer"], "wait=180");
}

#[tokio::test]
async fn lost_synchronous_query_is_not_replayed_and_cancel_prevents_a_new_request() {
    let server =
        MockServer::start(vec![MockResponse::json(TOKEN), MockResponse::status(504)]).unwrap();
    let (executor, compiled) = fixture(&server);
    let cancel = CancellationToken::new();
    assert!(executor.query(&compiled, &cancel).await.is_err());
    cancel.cancel();
    assert!(matches!(
        executor.query(&compiled, &cancel).await,
        Err(AppError::Cancelled)
    ));
    assert_eq!(server.finish().unwrap().len(), 2);
}
