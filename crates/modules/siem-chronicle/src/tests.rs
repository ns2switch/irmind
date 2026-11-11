use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use irmind_testkit::{MockResponse, MockServer};
use secrecy::SecretString;
use serde_json::{Value, json};
const RESPONSE: &str = r#"{"events":[],"moreDataAvailable":false}"#;
fn account() -> String {
    json!({"type":"service_account", "client_email":"synthetic@synthetic-project.iam.gserviceaccount.com",
        "token_uri":"https://oauth2.googleapis.com/token",
        "private_key":include_str!("../tests/fixtures/synthetic-service-account.pem")}).to_string()
}
fn config() -> ModuleConfig {
    let mut config = ModuleConfig::new();
    for (name, value) in [
        (
            "IRMIND_CHRONICLE_URL",
            "https://europe-west2-chronicle.googleapis.com/",
        ),
        ("IRMIND_CHRONICLE_SOURCE_ID", "chronicle-prod"),
        ("IRMIND_CHRONICLE_PROJECT", "synthetic-project"),
        ("IRMIND_CHRONICLE_LOCATION", "europe-west2"),
        ("IRMIND_CHRONICLE_INSTANCE", "synthetic-instance"),
        (
            "IRMIND_CHRONICLE_ACCOUNT_FIELD",
            "principal.administrative_domain",
        ),
    ] {
        config.insert_value(name, value.into());
    }
    config.insert_secret(
        "IRMIND_CHRONICLE_SERVICE_ACCOUNT_JSON",
        SecretString::from(account()),
    );
    config
}
fn port(api: &MockServer, oauth: &MockServer) -> Chronicle {
    let mut port = Chronicle::from_config(&config()).unwrap();
    port.endpoint = reqwest::Url::parse(api.origin()).unwrap();
    port.token_endpoint = reqwest::Url::parse(oauth.origin())
        .unwrap()
        .join("token")
        .unwrap();
    port
}
fn oauth() -> MockServer {
    MockServer::start(vec![MockResponse::json(
        r#"{"access_token":"synthetic-token","token_type":"Bearer","expires_in":3600}"#,
    )])
    .unwrap()
}
#[test]
fn common_siem_and_http_contracts() {
    irmind_testkit::run_siem_contract(&Chronicle::from_config(&config()).unwrap()).unwrap();
    irmind_testkit::run_http_safety_contract().unwrap();
}
#[test]
fn oauth_assertion_has_fixed_audience_scope_and_bounded_lifetime() {
    let port = Chronicle::from_config(&config()).unwrap();
    let signed = port.credentials.assertion(1000).unwrap();
    let parts = signed.expose_secret().split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header, json!({"alg":"RS256","typ":"JWT"}));
    assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
    assert_eq!(claims["scope"], "https://www.googleapis.com/auth/chronicle");
    assert_eq!(claims["iat"], 1000);
    assert_eq!(claims["exp"], 1300);
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    assert_eq!(signature.len(), 256);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        include_bytes!("../tests/fixtures/synthetic-public.der"),
    )
    .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
    .unwrap();
}
#[test]
fn search_forces_instance_account_time_and_structured_query() {
    let api = MockServer::start(vec![MockResponse::json(RESPONSE)]).unwrap();
    let oauth = oauth();
    let port = port(&api, &oauth);
    let requests = irmind_testkit::run_siem_recorded(&port, api, RESPONSE.as_bytes()).unwrap();
    let request = &requests[0];
    assert_eq!(request.method, "GET");
    assert_eq!(request.headers["authorization"], "Bearer synthetic-token");
    let url = reqwest::Url::parse(&format!("https://synthetic.invalid{}", request.target)).unwrap();
    assert_eq!(
        url.path(),
        "/v1alpha/projects/synthetic-project/locations/europe-west2/instances/synthetic-instance:udmSearch"
    );
    let pairs = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(pairs["queryDialect"], "YL2");
    assert_eq!(pairs["limit"], "20");
    assert!(pairs["query"].contains("principal.administrative_domain = \"123456789012\""));
    assert!(pairs["query"].contains("metadata.product_event_type = \"AssumeRole\""));
    assert!(pairs["timeRange.startTime"].starts_with("2026-10-23"));
    assert!(pairs["timeRange.endTime"].starts_with("2026-10-23"));
    let requests = oauth.finish().unwrap();
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/token");
    assert!(String::from_utf8_lossy(&requests[0].body).contains("jwt-bearer"));
}
#[test]
fn redirects_auth_errors_invalid_and_oversized_api_bodies_fail_closed() {
    let oversized = "x".repeat(5_000_001);
    for response in [
        MockResponse::redirect(),
        MockResponse::status(403),
        MockResponse::json(r#"{"events":"not-array"}"#),
        MockResponse::json(&oversized).allow_early_close(),
    ] {
        let api = MockServer::start(vec![response]).unwrap();
        let oauth = oauth();
        let port = port(&api, &oauth);
        assert!(irmind_testkit::run_siem_recorded(&port, api, RESPONSE.as_bytes()).is_err());
        oauth.finish().unwrap();
    }
}
#[test]
fn explicit_service_account_and_regional_origin_are_required_and_redacted() {
    for endpoint in [
        "http://europe-west2-chronicle.googleapis.com/",
        "https://wrong.invalid/",
        "https://europe-west2-chronicle.googleapis.com/?q=secret",
        "https://europe-west2-chronicle.googleapis.com/path/",
    ] {
        let mut config = config();
        config.insert_value("IRMIND_CHRONICLE_URL", endpoint.into());
        assert!(Chronicle::from_config(&config).is_err());
    }
    for field in ["token_uri", "private_key", "type"] {
        let mut account: Value = serde_json::from_str(&account()).unwrap();
        account[field] = Value::String("synthetic-secret-invalid".into());
        let mut config = config();
        config.insert_secret(
            "IRMIND_CHRONICLE_SERVICE_ACCOUNT_JSON",
            SecretString::from(account.to_string()),
        );
        let error = Chronicle::from_config(&config).unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-secret-invalid"));
    }
    let debug = format!("{:?}", Chronicle::from_config(&config()).unwrap());
    assert!(!debug.contains("PRIVATE KEY"));
    assert!(!debug.contains("synthetic-project"));
}

#[test]
fn token_cache_is_memory_only_and_errors_do_not_leak_authentication_data() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let oauth = oauth();
    let credentials = auth::Credentials::new(&SecretString::from(account())).unwrap();
    let client = irmind_http::client_builder(std::time::Duration::from_secs(2), true)
        .build()
        .unwrap();
    let endpoint = reqwest::Url::parse(oauth.origin())
        .unwrap()
        .join("token")
        .unwrap();
    runtime.block_on(async {
        let cancel = CancellationToken::new();
        for _ in 0..2 {
            assert_eq!(
                credentials
                    .token(&client, &endpoint, &cancel)
                    .await
                    .unwrap()
                    .expose_secret(),
                "synthetic-token"
            );
        }
    });
    assert_eq!(oauth.finish().unwrap().len(), 1);
    for response in [
        MockResponse::redirect(),
        MockResponse::status(401),
        MockResponse::json(
            r#"{"access_token":"synthetic-secret","token_type":"wrong","expires_in":3600}"#,
        ),
        MockResponse::json(
            r#"{"access_token":"synthetic-secret","token_type":"Bearer","expires_in":1}"#,
        ),
    ] {
        let server = MockServer::start(vec![response]).unwrap();
        let credentials = auth::Credentials::new(&SecretString::from(account())).unwrap();
        let url = reqwest::Url::parse(server.origin())
            .unwrap()
            .join("token")
            .unwrap();
        let error = runtime
            .block_on(credentials.token(&client, &url, &CancellationToken::new()))
            .unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-secret"));
        server.finish().unwrap();
    }
}
