#![allow(clippy::unwrap_used)]

use super::*;

fn port_for_server(origin: &str) -> Splunk {
    Splunk {
        async_client: reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        endpoint: reqwest::Url::parse(&format!("{origin}services/search/v2/jobs/export")).unwrap(),
        token: SecretString::from("synthetic-token".to_owned()),
        source_id: "splunk-prod".into(),
        index: "cloudtrail".into(),
        account_field: "recipientAccountId".into(),
        alert_id_field: "alert_id".into(),
        search_fields: SearchFields::from_config(&ModuleConfig::new()),
    }
}

#[test]
fn siem_contract() {
    let mut config = ModuleConfig::new();
    config.insert_value("IRMIND_SPLUNK_URL", "https://splunk.invalid/".into());
    config.insert_value("IRMIND_SPLUNK_SOURCE_ID", "splunk-prod".into());
    config.insert_value("IRMIND_SPLUNK_INDEX", "main".into());
    config.insert_value("IRMIND_SPLUNK_ACCOUNT_FIELD", "account".into());
    config.insert_secret(
        "IRMIND_SPLUNK_TOKEN",
        SecretString::from("test-token".to_owned()),
    );
    let port = Splunk::from_config(&config).unwrap();
    irmind_testkit::run_siem_contract(&port).unwrap();
    irmind_testkit::run_http_safety_contract().unwrap();
}

#[test]
fn recorded_siem_response_is_returned_as_evidence() {
    const RESPONSE: &str =
        "{\"result\":{\"eventName\":\"AssumeRole\",\"recipientAccountId\":\"123456789012\"}}\n";
    let server =
        irmind_testkit::MockServer::start(vec![irmind_testkit::MockResponse::json(RESPONSE)])
            .unwrap();
    let port = port_for_server(server.origin());
    let requests = irmind_testkit::run_siem_recorded(&port, server, RESPONSE.as_bytes()).unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("index%3Dcloudtrail"));
    assert!(body.contains("recipientAccountId%3D%22123456789012%22"));
    assert!(body.contains("eventName%3D%22AssumeRole%22"));
    assert!(body.contains("earliest_time="));
    assert!(body.contains("latest_time="));
    assert!(!body.contains("outputlookup"));
}

#[test]
fn recorded_alert_uses_exact_id_and_server_side_scope() {
    const RESPONSE: &str =
        "{\"result\":{\"alert_id\":\"synthetic-alert-1\",\"severity\":\"high\"}}\n";
    let server =
        irmind_testkit::MockServer::start(vec![irmind_testkit::MockResponse::json(RESPONSE)])
            .unwrap();
    let port = port_for_server(server.origin());
    let requests =
        irmind_testkit::run_siem_alert_recorded(&port, server, RESPONSE.as_bytes()).unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("index%3Dcloudtrail"));
    assert!(body.contains("recipientAccountId%3D%22123456789012%22"));
    assert!(body.contains("alert_id%3D%22synthetic-alert-1%22"));
    assert!(body.contains("earliest_time="));
    assert!(body.contains("latest_time="));
}

#[test]
fn generated_spl_uses_only_structured_fields_and_escaped_values() {
    let splunk = port_for_server("https://splunk.example/");
    let query = |field: &str, operator: &str, value: &str, aggregation: &str| {
        SiemQuery::parse(&std::collections::BTreeMap::from([
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("field".into(), field.into()),
            ("operator".into(), operator.into()),
            ("value".into(), value.into()),
            ("aggregation".into(), aggregation.into()),
            ("group_by".into(), "user".into()),
        ]))
        .unwrap()
    };
    assert_eq!(
        splunk
            .spl_search(
                "123456789012",
                &SiemQuery::parse(&std::collections::BTreeMap::from([
                    ("from".into(), "2026-10-23T12:00:00Z".into()),
                    ("to".into(), "2026-10-23T13:00:00Z".into()),
                    ("field".into(), "event_name".into()),
                    ("operator".into(), "eq".into()),
                    ("value".into(), "AssumeRole".into()),
                ]))
                .unwrap()
            )
            .unwrap(),
        "search index=cloudtrail recipientAccountId=\"123456789012\" eventName=\"AssumeRole\" | head 20"
    );
    assert_eq!(
        splunk
            .spl_search(
                "123456789012",
                &query("event_name", "not_eq", "A\"B\\C", "count_by")
            )
            .unwrap(),
        "search index=cloudtrail recipientAccountId=\"123456789012\" eventName!=\"A\\\"B\\\\C\" | stats count by user | head 20"
    );
    assert!(
        splunk
            .spl_search("123\" | sendemail", &query("event_name", "eq", "ok", "top"))
            .is_err()
    );
    assert!(splunk.spl_alert("123456789012", "id\" | collect").is_err());
    assert_eq!(
        splunk
            .spl_alert("123456789012", "synthetic-alert-1")
            .unwrap(),
        "search index=cloudtrail recipientAccountId=\"123456789012\" alert_id=\"synthetic-alert-1\" | head 1"
    );
}

#[test]
fn aggregation_and_field_mapping_remain_bounded() {
    let mut splunk = port_for_server("https://splunk.example/");
    let mut config = ModuleConfig::new();
    config.insert_value("IRMIND_SPLUNK_USER_FIELD", "userIdentity.arn".into());
    splunk.search_fields = SearchFields::from_config(&config);
    let query = |operator: &str, aggregation: &str, group_by: &str, limit: &str| {
        SiemQuery::parse(&std::collections::BTreeMap::from([
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("field".into(), "source_ip".into()),
            ("operator".into(), operator.into()),
            ("value".into(), "192.0.2.".into()),
            ("aggregation".into(), aggregation.into()),
            ("group_by".into(), group_by.into()),
            ("limit".into(), limit.into()),
        ]))
        .unwrap()
    };
    let top = splunk
        .spl_search("123456789012", &query("prefix", "top", "user", "5"))
        .unwrap();
    assert!(top.contains("sourceIPAddress=\"192.0.2.*\""));
    assert!(top.ends_with("| top limit=5 \"userIdentity.arn\""));
    let distinct = splunk
        .spl_search("123456789012", &query("eq", "distinct", "host", "7"))
        .unwrap();
    assert!(distinct.ends_with("| dedup host | table host | head 7"));
}

#[test]
fn configured_search_fields_cannot_contain_spl_commands() {
    let mut config = ModuleConfig::new();
    config.insert_value("IRMIND_SPLUNK_URL", "https://splunk.invalid/".into());
    config.insert_value("IRMIND_SPLUNK_SOURCE_ID", "splunk-prod".into());
    config.insert_value("IRMIND_SPLUNK_INDEX", "cloudtrail".into());
    config.insert_value("IRMIND_SPLUNK_ACCOUNT_FIELD", "recipientAccountId".into());
    config.insert_value("IRMIND_SPLUNK_USER_FIELD", "user | delete".into());
    config.insert_secret(
        "IRMIND_SPLUNK_TOKEN",
        SecretString::from("synthetic-token".to_owned()),
    );
    assert!(Splunk::from_config(&config).is_err());
}

#[test]
fn connector_rejects_unapproved_ca_file() {
    let mut config = ModuleConfig::new();
    config.insert_value("IRMIND_SPLUNK_URL", "https://splunk.invalid/".into());
    config.insert_value("IRMIND_SPLUNK_SOURCE_ID", "splunk-prod".into());
    config.insert_value("IRMIND_SPLUNK_INDEX", "cloudtrail".into());
    config.insert_value("IRMIND_SPLUNK_ACCOUNT_FIELD", "recipientAccountId".into());
    config.insert_value(
        "IRMIND_SPLUNK_CA_PEM",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../http/tests/fixtures/ca.pem"
        )
        .into(),
    );
    config.insert_value("IRMIND_SPLUNK_CA_SHA256", "0".repeat(64));
    config.insert_secret(
        "IRMIND_SPLUNK_TOKEN",
        SecretString::from("synthetic-token".to_owned()),
    );
    let error = Splunk::from_config(&config).err().unwrap();
    assert!(error.to_string().contains("fingerprint"));
    assert!(!error.to_string().contains("synthetic-token"));
}
