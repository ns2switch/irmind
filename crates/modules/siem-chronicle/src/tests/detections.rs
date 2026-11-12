#![allow(clippy::panic)]
use super::*;
use irmind_domain::{Decision, ExecutionMode, ProposedCall, Tool, evaluate};
fn alert(account: &str) -> irmind_domain::AuthorizedCall {
    let case = irmind_domain::Case {
        id: irmind_domain::CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
        title: "Synthetic".into(),
        severity: irmind_domain::Severity::Medium,
        scope: format!(
            "v1;sources=chronicle-prod;accounts={account};hosts=;from=2026-11-01T00:00:00Z;to=2026-11-02T00:00:00Z"
        ),
        sealed: false,
    };
    let call = ProposedCall {
        tool: Tool::SiemGetAlert,
        args: std::collections::BTreeMap::from([
            ("source".into(), "chronicle-prod".into()),
            ("account".into(), account.into()),
            ("from".into(), "2026-11-01T00:00:00Z".into()),
            ("to".into(), "2026-11-02T00:00:00Z".into()),
            ("alert_id".into(), "de-synthetic".into()),
        ]),
    };
    let Decision::Allow(call) = evaluate(&case, call, 1, ExecutionMode::Attended, 0) else {
        panic!("synthetic alert was not authorized")
    };
    call
}
pub(super) fn instance(api: &MockServer, oauth: &MockServer) -> Chronicle {
    let mut port = port(api, oauth);
    port.scope_mode = irmind_app::SiemScopeMode::Instance;
    port.rule_id = Some("ru-synthetic".into());
    port
}
#[tokio::test]
async fn instance_detection_fixes_rule_resource_window_and_exact_id() {
    let api = MockServer::start(vec![MockResponse::json(r#"{"detections":[{"id":"de-other","detectionTime":"2026-11-01T01:00:00Z"},{"id":"de-synthetic","detectionTime":"2026-11-01T02:00:00.123456789Z","detection":[{"ruleId":"ru-synthetic"}]}]}"#)]).unwrap();
    let oauth = oauth();
    let port = instance(&api, &oauth);
    let result = port
        .execute(&alert("synthetic-project"), &CancellationToken::new())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(value["detections"].as_array().unwrap().len(), 1);
    assert_eq!(value["detections"][0]["id"], "de-synthetic");
    assert_eq!(value["partial"], false);
    let request = api.finish().unwrap();
    assert!(
        request[0]
            .target
            .contains("legacy%3AlegacySearchDetections")
            || request[0].target.contains("legacy:legacySearchDetections")
    );
    assert!(request[0].target.contains("ruleId=ru-synthetic"));
    assert!(request[0].target.contains("listBasis=DETECTION_TIME"));
    assert!(request[0].target.contains("startTime="));
    assert!(request[0].target.contains("endTime="));
}
#[tokio::test]
async fn default_mode_and_wrong_instance_account_fail_before_authentication() {
    let api = MockServer::start(vec![]).unwrap();
    let oauth = MockServer::start(vec![]).unwrap();
    assert!(
        port(&api, &oauth)
            .execute(&alert("synthetic-project"), &CancellationToken::new())
            .await
            .is_err()
    );
    assert!(
        instance(&api, &oauth)
            .execute(&alert("other-project"), &CancellationToken::new())
            .await
            .is_err()
    );
    assert!(api.finish().unwrap().is_empty());
    assert!(oauth.finish().unwrap().is_empty());
}
#[tokio::test]
async fn four_page_scan_is_partial_and_never_claims_definitive_absence() {
    let api = MockServer::start(
        (1..=4)
            .map(|n| {
                MockResponse::json(&format!(
                    r#"{{"detections":[],"nextPageToken":"page-{n}"}}"#
                ))
            })
            .collect(),
    )
    .unwrap();
    let oauth = oauth();
    let port = instance(&api, &oauth);
    let result = port
        .execute(&alert("synthetic-project"), &CancellationToken::new())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(value["status"], "partial_not_found");
    assert_eq!(value["partial"], true);
    assert_eq!(api.finish().unwrap().len(), 4);
}
#[tokio::test]
async fn repeated_pagination_token_and_outside_window_are_rejected() {
    for pages in [
        vec![r#"{"nextPageToken":"same"}"#, r#"{"nextPageToken":"same"}"#],
        vec![r#"{"detections":[{"id":"de-synthetic","detectionTime":"2026-11-02T00:00:00Z"}]}"#],
    ] {
        let api = MockServer::start(pages.into_iter().map(MockResponse::json).collect()).unwrap();
        let oauth = oauth();
        assert!(
            instance(&api, &oauth)
                .execute(&alert("synthetic-project"), &CancellationToken::new())
                .await
                .is_err()
        );
    }
}
#[test]
fn mode_is_closed_and_rule_wildcards_cannot_expand_the_configured_namespace() {
    for mode in ["automatic", "*", "INSTANCE"] {
        let mut config = config();
        config.insert_value("IRMIND_CHRONICLE_SCOPE_MODE", mode.into());
        assert!(Chronicle::from_config(&config).is_err());
    }
    let mut config = config();
    config.insert_value("IRMIND_CHRONICLE_RULE_ID", "*".into());
    assert!(Chronicle::from_config(&config).is_err());
}
#[test]
fn instance_search_uses_the_fixed_resource_without_an_event_account_predicate() {
    let api = MockServer::start(vec![]).unwrap();
    let oauth = MockServer::start(vec![]).unwrap();
    let port = instance(&api, &oauth);
    let authorized = irmind_domain::evaluate(
        &irmind_domain::Case {
            id: irmind_domain::CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            title: "Synthetic".into(),
            severity: irmind_domain::Severity::Medium,
            scope: super::scope::SCOPE.into(),
            sealed: false,
        },
        super::scope::search(),
        1,
        ExecutionMode::Attended,
        0,
    );
    let Decision::Allow(call) = authorized else {
        panic!("synthetic query denied")
    };
    let url = port.search_url(&call).unwrap();
    assert!(url.path().contains(
        "projects/synthetic-project/locations/europe-west2/instances/synthetic-instance"
    ));
    let pairs = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(!pairs["query"].contains("principal.administrative_domain"));
    assert!(pairs["query"].contains("alice"));
}
#[tokio::test]
async fn provider_truncation_and_record_budget_keep_the_partial_marker() {
    let rows = (0..20)
        .map(|n| {
            serde_json::json!({
                "id":format!("other-{n}"), "detectionTime":"2026-11-01T01:00:00Z"
            })
        })
        .collect::<Vec<_>>();
    let response = serde_json::json!({"detections": rows, "nextPageToken":"more", "respTooLargeDetectionsTruncated":true});
    let api = MockServer::start(vec![MockResponse::json(&response.to_string())]).unwrap();
    let oauth = oauth();
    let bytes = instance(&api, &oauth)
        .execute(&alert("synthetic-project"), &CancellationToken::new())
        .await
        .unwrap();
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["scanned"], 20);
    assert_eq!(result["partial"], true);
    assert_eq!(result["status"], "partial_not_found");
    assert_eq!(api.finish().unwrap().len(), 1);
}
#[tokio::test]
async fn detection_receipt_bytes_do_not_depend_on_provider_object_key_order() {
    let mut receipts = Vec::new();
    for response in [
        r#"{"detections":[{"id":"de-synthetic","metadata":{"z":2,"a":1},"detectionTime":"2026-11-01T01:00:00Z"}]}"#,
        r#"{"detections":[{"detectionTime":"2026-11-01T01:00:00Z","metadata":{"a":1,"z":2},"id":"de-synthetic"}]}"#,
    ] {
        let api = MockServer::start(vec![MockResponse::json(response)]).unwrap();
        let oauth = oauth();
        receipts.push(
            instance(&api, &oauth)
                .execute(&alert("synthetic-project"), &CancellationToken::new())
                .await
                .unwrap(),
        );
        assert_eq!(api.finish().unwrap().len(), 1);
        assert_eq!(oauth.finish().unwrap().len(), 1);
    }
    assert_eq!(receipts[0], receipts[1]);
    assert_eq!(
        std::str::from_utf8(&receipts[0]).unwrap(),
        r#"{"detections":[{"detectionTime":"2026-11-01T01:00:00Z","id":"de-synthetic","metadata":{"a":1,"z":2}}],"pages":1,"partial":false,"requested_id":"de-synthetic","scanned":1,"scope_mode":"instance","status":"found","truncated":false}"#
    );
}
