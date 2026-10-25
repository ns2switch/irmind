#![forbid(unsafe_code)]

use aws_config::{BehaviorVersion, Region};
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_cloudtrail::{
    primitives::DateTime as AwsDateTime,
    types::{LookupAttribute, LookupAttributeKey},
};
use chrono::DateTime;
use irmind_app::{
    AppError, CancellationToken, CloudAuditPort, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use secrecy::ExposeSecret;
use serde_json::{Value, json};

pub struct AwsCloudTrail {
    cloudtrail: aws_sdk_cloudtrail::Client,
    iam: aws_sdk_iam::Client,
    sts: aws_sdk_sts::Client,
    source_id: String,
    role_name: String,
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "cloud-aws",
    version: "0.1.0",
    ports: &[ModulePort::CloudAudit],
    tools: &[Tool::CloudAuditEvents, Tool::CloudIdentity],
    config: &[
        ConfigField {
            name: "IRMIND_AWS_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_AWS_REGION",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_AWS_ROLE_NAME",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "AWS_ACCESS_KEY_ID",
            required: true,
            secret: true,
        },
        ConfigField {
            name: "AWS_SECRET_ACCESS_KEY",
            required: true,
            secret: true,
        },
        ConfigField {
            name: "AWS_SESSION_TOKEN",
            required: false,
            secret: true,
        },
    ],
};

impl Module for AwsCloudTrail {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_cloud_audit(self)
    }
}

impl AwsCloudTrail {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let source_id = config.required_value("IRMIND_AWS_SOURCE_ID")?.to_owned();
        let region = config.required_value("IRMIND_AWS_REGION")?.to_owned();
        let role_name = config.required_value("IRMIND_AWS_ROLE_NAME")?.to_owned();
        let access_key = config.required_secret("AWS_ACCESS_KEY_ID")?.expose_secret();
        let secret_key = config
            .required_secret("AWS_SECRET_ACCESS_KEY")?
            .expose_secret();
        let session_token = config
            .secret("AWS_SESSION_TOKEN")
            .map(|value| value.expose_secret().to_owned());
        if access_key.is_empty() || secret_key.is_empty() {
            return Err(AppError::Policy("empty AWS credential".into()));
        }
        if !safe_name(&source_id, 64) || !safe_name(&region, 32) || !region.contains('-') {
            return Err(AppError::Policy("invalid AWS source ID or region".into()));
        }
        if !safe_name(&role_name, 64) {
            return Err(AppError::Policy("invalid AWS role name".into()));
        }
        let config = aws_config::SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region))
            .timeout_config(
                aws_config::timeout::TimeoutConfig::builder()
                    .connect_timeout(std::time::Duration::from_secs(10))
                    .read_timeout(std::time::Duration::from_secs(30))
                    .operation_attempt_timeout(std::time::Duration::from_secs(45))
                    .operation_timeout(std::time::Duration::from_secs(90))
                    .build(),
            )
            .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                access_key,
                secret_key,
                session_token,
                None,
                "irmind-keyring",
            )))
            .build();
        Ok(Self {
            cloudtrail: aws_sdk_cloudtrail::Client::new(&config),
            iam: aws_sdk_iam::Client::new(&config),
            sts: aws_sdk_sts::Client::new(&config),
            source_id,
            role_name,
        })
    }

    async fn verify_aws_identity(&self, account: &str) -> Result<(), AppError> {
        let identity = self
            .sts
            .get_caller_identity()
            .send()
            .await
            .map_err(|_| AppError::Storage("AWS STS identity lookup failed".into()))?;
        if identity.account() != Some(account) {
            return Err(AppError::Policy(
                "AWS credential account differs from case scope".into(),
            ));
        }
        if !identity.arn().is_some_and(|arn| {
            arn.contains(&format!(":assumed-role/{}/", self.role_name))
                || arn.ends_with(&format!(":role/{}", self.role_name))
        }) {
            return Err(AppError::Policy(
                "AWS credentials do not use the dedicated role".into(),
            ));
        }
        Ok(())
    }

    async fn events_async(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        let request = CloudRequest::from_call(call, self.source_id())?;
        self.verify_aws_identity(request.account).await?;
        let attribute = LookupAttribute::builder()
            .attribute_key(LookupAttributeKey::EventName)
            .attribute_value(request.event_name)
            .build()
            .map_err(|_| AppError::Policy("invalid CloudTrail event name".into()))?;
        let output = self
            .cloudtrail
            .lookup_events()
            .lookup_attributes(attribute)
            .start_time(AwsDateTime::from_secs(request.from))
            .end_time(AwsDateTime::from_secs(request.to))
            .max_results(20)
            .send()
            .await
            .map_err(|_| AppError::Storage("CloudTrail LookupEvents failed".into()))?;
        let events = output
            .events()
            .iter()
            .filter_map(|event| event.cloud_trail_event())
            .map(|record| serde_json::from_str::<Value>(record).unwrap_or_else(|_| json!(record)))
            .collect::<Vec<_>>();
        let raw = serde_json::to_vec(&json!({
            "source": self.source_id,
            "account": request.account,
            "events": events,
            "truncated": output.next_token().is_some()
        }))
        .map_err(|error| AppError::Storage(error.to_string()))?;
        if raw.len() > 5_000_000 {
            return Err(AppError::Policy("CloudTrail response exceeds 5 MB".into()));
        }
        Ok(raw)
    }

    async fn identity_async(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::CloudIdentity || call.arg("source") != Some(self.source_id()) {
            return Err(AppError::Policy("wrong AWS identity source or tool".into()));
        }
        let account = call
            .arg("account")
            .ok_or_else(|| AppError::Policy("missing AWS account".into()))?;
        let kind = call
            .arg("kind")
            .ok_or_else(|| AppError::Policy("missing IAM identity kind".into()))?;
        let name = call
            .arg("name")
            .ok_or_else(|| AppError::Policy("missing IAM identity name".into()))?;
        if account.len() != 12
            || !account.bytes().all(|byte| byte.is_ascii_digit())
            || name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_+=,.@-".contains(&byte))
        {
            return Err(AppError::Policy("invalid AWS identity request".into()));
        }
        self.verify_aws_identity(account).await?;
        let value = match kind {
            "role" => {
                let output = self
                    .iam
                    .get_role()
                    .role_name(name)
                    .send()
                    .await
                    .map_err(|_| AppError::Storage("AWS IAM GetRole failed".into()))?;
                let role = output
                    .role()
                    .ok_or_else(|| AppError::Storage("AWS IAM role missing".into()))?;
                json!({"kind":"role","name":role.role_name(),"arn":role.arn(),"id":role.role_id()})
            }
            "user" => {
                let output = self
                    .iam
                    .get_user()
                    .user_name(name)
                    .send()
                    .await
                    .map_err(|_| AppError::Storage("AWS IAM GetUser failed".into()))?;
                let user = output
                    .user()
                    .ok_or_else(|| AppError::Storage("AWS IAM user missing".into()))?;
                json!({"kind":"user","name":user.user_name(),"arn":user.arn(),"id":user.user_id()})
            }
            _ => return Err(AppError::Policy("unsupported IAM identity kind".into())),
        };
        serde_json::to_vec(&value).map_err(|error| AppError::Storage(error.to_string()))
    }
}

#[async_trait]
impl CloudAuditPort for AwsCloudTrail {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AppError::Cancelled),
            result = async {
                match call.tool() {
                    Tool::CloudAuditEvents => self.events_async(call).await,
                    Tool::CloudIdentity => self.identity_async(call).await,
                    _ => Err(AppError::Policy("invalid cloud tool".into())),
                }
            } => result,
        }
    }
}

struct CloudRequest<'a> {
    account: &'a str,
    event_name: &'a str,
    from: i64,
    to: i64,
}

impl<'a> CloudRequest<'a> {
    fn from_call(call: &'a AuthorizedCall, source_id: &str) -> Result<Self, AppError> {
        if call.tool() != &Tool::CloudAuditEvents || call.arg("source") != Some(source_id) {
            return Err(AppError::Policy("wrong CloudTrail source or tool".into()));
        }
        let account = call
            .arg("account")
            .ok_or_else(|| AppError::Policy("missing AWS account".into()))?;
        let event_name = call
            .arg("event_name")
            .ok_or_else(|| AppError::Policy("missing CloudTrail event name".into()))?;
        let from = parse_utc(call.arg("from"))?;
        let to = parse_utc(call.arg("to"))?;
        if account.len() != 12
            || !account.bytes().all(|byte| byte.is_ascii_digit())
            || !safe_name(event_name, 128)
            || !(1..=86_400).contains(&(to - from))
        {
            return Err(AppError::Policy(
                "invalid bounded CloudTrail request".into(),
            ));
        }
        Ok(Self {
            account,
            event_name,
            from,
            to,
        })
    }
}

fn parse_utc(value: Option<&str>) -> Result<i64, AppError> {
    let value = value.ok_or_else(|| AppError::Policy("missing CloudTrail time".into()))?;
    if value.len() != 20 || !value.ends_with('Z') {
        return Err(AppError::Policy(
            "CloudTrail requires UTC second precision".into(),
        ));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.timestamp())
        .map_err(|_| AppError::Policy("invalid CloudTrail time".into()))
}

fn safe_name(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
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
        let Decision::Allow(call) = evaluate(&case, proposal, 1, ExecutionMode::Attended) else {
            panic!("scoped cloud read should be authorized");
        };
        let request = CloudRequest::from_call(&call, "aws-prod").unwrap();
        assert_eq!(request.to - request.from, 3600);
        assert!(CloudRequest::from_call(&call, "other").is_err());
    }
}
