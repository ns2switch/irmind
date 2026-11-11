use super::*;
use irmind_app::modules::ModuleConfig;
use irmind_testkit::{MockResponse, MockServer};
const RESPONSE: &str = r#"{"timed_out":false,"_shards":{"failed":0},"hits":{"hits":[]}}"#;
fn config() -> ModuleConfig {
    let mut config = ModuleConfig::new();
    for (name, value) in [
        ("IRMIND_ELASTIC_URL", "https://elastic.invalid/"),
        ("IRMIND_ELASTIC_SOURCE_ID", "elastic-prod"),
        ("IRMIND_ELASTIC_INDICES", "logs-*,audit-events"),
        ("IRMIND_ELASTIC_ALERT_SPACE", "default"),
        ("IRMIND_ELASTIC_ACCOUNT_FIELD", "cloud.account.id"),
    ] {
        config.insert_value(name, value.into());
    }
    config.insert_secret(
        "IRMIND_ELASTIC_API_KEY",
        SecretString::from("synthetic-api-key".to_owned()),
    );
    config
}
fn server_port(server: &MockServer) -> Elastic {
    let mut port = Elastic::from_config(&config()).unwrap();
    port.origin = reqwest::Url::parse(server.origin()).unwrap();
    port
}
#[test]
fn common_siem_and_http_contracts() {
    irmind_testkit::run_siem_contract(&Elastic::from_config(&config()).unwrap()).unwrap();
    irmind_testkit::run_http_safety_contract().unwrap();
}
#[test]
fn search_forces_index_account_and_time_on_server() {
    let server = MockServer::start(vec![MockResponse::json(RESPONSE)]).unwrap();
    let port = server_port(&server);
    let requests = irmind_testkit::run_siem_recorded(&port, server, RESPONSE.as_bytes()).unwrap();
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/logs-*,audit-events/_search");
    assert_eq!(
        request.headers.get("authorization").unwrap(),
        "ApiKey synthetic-api-key"
    );
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(
        body.pointer("/query/bool/filter/0/term/cloud.account.id"),
        Some(&serde_json::json!("123456789012"))
    );
    assert!(
        body.pointer("/query/bool/filter/1/range/@timestamp/gte")
            .is_some()
    );
    assert!(
        body.pointer("/query/bool/filter/1/range/@timestamp/lt")
            .is_some()
    );
    assert_eq!(
        body.pointer("/query/bool/filter/2/term/event.action"),
        Some(&serde_json::json!("AssumeRole"))
    );
    assert_eq!(body["timeout"], "30s");
    assert_eq!(body["size"], 20);
    assert!(body.get("script").is_none());
}
#[test]
fn alert_uses_one_space_exact_id_and_same_server_filters() {
    let server = MockServer::start(vec![MockResponse::json(RESPONSE)]).unwrap();
    let port = server_port(&server);
    let requests =
        irmind_testkit::run_siem_alert_recorded(&port, server, RESPONSE.as_bytes()).unwrap();
    assert_eq!(
        requests[0].target,
        "/.alerts-security.alerts-default/_search"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body.pointer("/query/bool/filter/2/term/kibana.alert.uuid"),
        Some(&serde_json::json!("synthetic-alert-1"))
    );
    assert!(
        body.pointer("/query/bool/filter/0/term/cloud.account.id")
            .is_some()
    );
    assert!(
        body.pointer("/query/bool/filter/1/range/@timestamp")
            .is_some()
    );
    assert_eq!(body["_source"], false);
    assert!(body["fields"].is_array());
}
#[test]
fn partial_provider_results_keep_their_explicit_markers() {
    const PARTIAL: &str = r#"{"timed_out":true,"_shards":{"failed":1},"hits":{"hits":[]}}"#;
    let server = MockServer::start(vec![MockResponse::json(PARTIAL)]).unwrap();
    let port = server_port(&server);
    irmind_testkit::run_siem_recorded(&port, server, PARTIAL.as_bytes()).unwrap();
}
#[test]
fn rejects_redirect_errors_malformed_and_oversized_responses() {
    let oversized = "x".repeat(5_000_001);
    for response in [
        MockResponse::redirect(),
        MockResponse::status(401),
        MockResponse::json("{}"),
        MockResponse::json(&oversized).allow_early_close(),
    ] {
        let server = MockServer::start(vec![response]).unwrap();
        let port = server_port(&server);
        assert!(irmind_testkit::run_siem_recorded(&port, server, RESPONSE.as_bytes()).is_err());
    }
}
#[test]
fn rejects_invalid_configuration_and_never_formats_secrets() {
    for url in [
        "http://elastic.invalid/",
        "https://user:pass@elastic.invalid/",
        "https://elastic.invalid/?q=a",
        "https://elastic.invalid/path/",
    ] {
        let mut config = config();
        config.insert_value("IRMIND_ELASTIC_URL", url.into());
        let error = Elastic::from_config(&config).unwrap_err();
        assert!(!error.to_string().contains("pass@"));
    }
    for indices in [
        "*",
        "logs-*,*",
        "remote:logs-*",
        "logs-*/_delete_by_query",
        "logs-?",
        "logs-*,",
        "logs-* ",
    ] {
        let mut config = config();
        config.insert_value("IRMIND_ELASTIC_INDICES", indices.into());
        assert!(Elastic::from_config(&config).is_err());
    }
    for space in ["*", "default-*", "../default", "default/other"] {
        let mut config = config();
        config.insert_value("IRMIND_ELASTIC_ALERT_SPACE", space.into());
        assert!(Elastic::from_config(&config).is_err());
    }
    let port = Elastic::from_config(&config()).unwrap();
    let debug = format!("{port:?}");
    assert!(!debug.contains("synthetic-api-key"));
    assert!(!debug.contains("elastic.invalid"));
}
