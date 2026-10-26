use super::*;
use irmind_domain::{Case, CaseId, Decision, ExecutionMode, ProposedCall, Severity, evaluate};
use std::collections::BTreeMap;

#[test]
fn cloud_audit_contract() {
    let mut config = ModuleConfig::new();
    config.insert_value("IRMIND_AWS_SOURCE_ID", "aws-prod".into());
    config.insert_value("IRMIND_AWS_REGION", "eu-west-1".into());
    config.insert_value("IRMIND_AWS_ROLE_NAME", "SecurityAudit".into());
    config.insert_secret(
        "AWS_ACCESS_KEY_ID",
        secrecy::SecretString::from("test-access".to_owned()),
    );
    config.insert_secret(
        "AWS_SECRET_ACCESS_KEY",
        secrecy::SecretString::from("test-secret".to_owned()),
    );
    let port = AwsCloudTrail::from_config(&config).unwrap();
    irmind_testkit::run_cloud_audit_contract(&port).unwrap();
}

#[test]
fn recorded_sts_and_cloudtrail_responses_produce_evidence() {
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    let sts = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/IRMindReadOnly/synthetic</Arn><Account>123456789012</Account><UserId>AROAEXAMPLE:synthetic</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>"#;
    let trail = r#"{"Events":[{"EventId":"11111111-1111-1111-1111-111111111111","EventName":"AssumeRole","CloudTrailEvent":"{\"eventName\":\"AssumeRole\",\"userAgent\":\"synthetic-test\"}"}]}"#;
    let replay = StaticReplayClient::new(vec![
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://sts.eu-west-1.amazonaws.com/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(200)
                .header("content-type", "text/xml")
                .body(SdkBody::from(sts))
                .unwrap(),
        ),
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://cloudtrail.eu-west-1.amazonaws.com/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .body(SdkBody::from(trail))
                .unwrap(),
        ),
    ]);
    let config = aws_config::SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("eu-west-1"))
        .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
            "AKIATEST",
            "synthetic-secret",
            None,
            None,
            "test",
        )))
        .http_client(replay)
        .build();
    let port = AwsCloudTrail {
        cloudtrail: aws_sdk_cloudtrail::Client::new(&config),
        iam: aws_sdk_iam::Client::new(&config),
        sts: aws_sdk_sts::Client::new(&config),
        source_id: "aws-prod".into(),
        role_name: "IRMindReadOnly".into(),
    };
    let bytes = irmind_testkit::run_cloud_audit_recorded(&port, "synthetic-test").unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["events"].is_array());
}

#[test]
fn authorized_cloud_request_is_bounded_before_sdk_dispatch() {
    let case = Case {
            id: CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap(),
            title: "AWS".into(),
            severity: Severity::Medium,
            scope: "v1;sources=aws-prod;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into(),
            sealed: false,
        };
    let proposal = ProposedCall {
        tool: Tool::CloudAuditEvents,
        args: BTreeMap::from([
            ("source".into(), "aws-prod".into()),
            ("account".into(), "123456789012".into()),
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("event_name".into(), "AssumeRole".into()),
        ]),
    };
    let Decision::Allow(call) =
        evaluate(&case, proposal, 1, ExecutionMode::Attended, 1_700_000_000)
    else {
        panic!("scoped cloud read should be authorized");
    };
    let request = CloudRequest::from_call(&call, "aws-prod").unwrap();
    assert_eq!(request.to - request.from, 3600);
    assert!(CloudRequest::from_call(&call, "other").is_err());
}
