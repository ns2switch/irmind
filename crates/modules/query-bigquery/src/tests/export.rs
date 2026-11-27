use super::*;

#[path = "../../../../testkit/provider_tests/source_query_export.rs"]
mod case_contract;

const TOKEN: &str = "synthetic-bigquery-export-bearer";
const KEY: &str =
    include_str!("../../../siem-chronicle/tests/fixtures/synthetic-service-account.pem");
const PAGE: &[u8] = include_bytes!("../../../../../fuzz/seeds/query_page_bigquery/page.json");

#[test]
fn real_clock_preflight_and_exact_v9_citation_with_oauth_without_exported_credentials() {
    let (source, limits, mut query) = compiled_fixture();
    query["filters"] = json!([]);
    let fixture = case_contract::Fixture {
        source: serde_json::from_value(source).unwrap(),
        limits,
        query,
        billed_bytes: 10 << 20,
        citation_field: "insertId",
    };
    let server = query_server();
    let oauth = MockServer::start(vec![MockResponse::json(
        &json!({
            "access_token":TOKEN,"token_type":"Bearer","expires_in":300
        })
        .to_string(),
    )])
    .unwrap();
    let mut executor = connect(&fixture.source, &fixture.limits, &server, &oauth);
    let clock = Arc::new(case_contract::ObservedClock::default());
    executor.clock = clock.clone();
    let bytes = case_contract::acquire_and_export(
        &fixture,
        executor,
        BigQueryCaptureDecoder,
        irmind_mod_mapping_gcp_audit::CloudAuditMapping::for_capture().unwrap(),
        clock.as_ref(),
    );
    let requests = oauth.finish().unwrap();
    let body = std::str::from_utf8(&requests[0].body).unwrap();
    let assertion = body.split("assertion=").nth(1).unwrap();
    assert_eq!(assertion.split('.').count(), 3);
    assert_eq!(server.finish().unwrap().len(), 4);
    for secret in [TOKEN, assertion].into_iter().chain(KEY.lines()) {
        assert!(
            !contains(&bytes, secret.as_bytes()),
            "authentication material in export"
        );
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn connect(
    source: &ResolvedQuerySourceV1,
    limits: &SourceQueryLimits,
    server: &MockServer,
    oauth: &MockServer,
) -> BigQuery {
    let account = SecretString::from(json!({
        "type":"service_account","client_email":"synthetic-export@gcp-test.iam.gserviceaccount.com",
        "private_key":KEY,"token_uri":"https://oauth2.googleapis.com/token"
    }).to_string());
    let mut executor = BigQuery::with_service_account(
        source.clone(),
        limits.clone(),
        &account,
        Arc::new(irmind_infra::SystemClock),
    )
    .unwrap();
    executor.endpoint = reqwest::Url::parse(server.origin())
        .unwrap()
        .join("bigquery/v2/")
        .unwrap();
    let Credentials::ServiceAccount { endpoint, .. } = &mut executor.credentials else {
        unreachable!()
    };
    *endpoint = reqwest::Url::parse(oauth.origin())
        .unwrap()
        .join("token")
        .unwrap();
    executor
}

fn query_server() -> MockServer {
    let mut submission = Value::Null;
    MockServer::start_with(4, move |step, request| {
        assert_eq!(request.headers.get("authorization").map(String::as_str), Some("Bearer synthetic-bigquery-export-bearer"));
        let response = match step {
            0 => json!({"configuration":{"dryRun":true},"statistics":{"query":{"totalBytesProcessed":"128"}}}),
            1 => {
                submission = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(submission["configuration"]["query"]["maximumBytesBilled"], "67108864");
                json!({"jobReference":submission["jobReference"]})
            }
            2 => {
                let job_id = submission["jobReference"]["jobId"].as_str().unwrap();
                assert!(request.target.contains(&format!("/jobs/{job_id}?")));
                json!({"jobReference":submission["jobReference"],"configuration":submission["configuration"],
                    "status":{"state":"DONE"},"statistics":{"query":{"totalBytesProcessed":"128","totalBytesBilled":"10485760"}}})
            }
            3 => {
                let job_id = submission["jobReference"]["jobId"].as_str().unwrap();
                assert!(request.target.contains(&format!("/queries/{job_id}?")));
                let mut page: Value = serde_json::from_slice(PAGE).unwrap();
                page["jobReference"] = submission["jobReference"].clone();
                let rows = page["rows"].as_array_mut().unwrap();
                rows[0]["f"][0]["v"] = json!("1794830400123456");
                rows[0]["f"][1]["v"] = json!(case_contract::FIRST);
                let mut second = rows[0].clone();
                second["f"][1]["v"] = json!(case_contract::CITED);
                rows.push(second);
                page["totalRows"] = json!("2");
                page
            }
            _ => unreachable!(),
        };
        Ok(MockResponse::json(&response.to_string()))
    }).unwrap()
}
