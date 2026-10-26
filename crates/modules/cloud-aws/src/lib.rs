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
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::EmptyAWSCredential,
            )));
        }
        if !safe_name(&source_id, 64) || !safe_name(&region, 32) || !region.contains('-') {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidAWSSourceIDOrRegion,
            )));
        }
        if !safe_name(&role_name, 64) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidAWSRoleName,
            )));
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
        let identity = self.sts.get_caller_identity().send().await.map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::AWSSTSIdentityLookupFailed,
            ))
        })?;
        if identity.account() != Some(account) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::AWSCredentialAccountDiffersFromCaseScope,
            )));
        }
        if !identity.arn().is_some_and(|arn| {
            arn.contains(&format!(":assumed-role/{}/", self.role_name))
                || arn.ends_with(&format!(":role/{}", self.role_name))
        }) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::AWSCredentialsDoNotUseTheDedicatedRole,
            )));
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
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::InvalidCloudTrailEventName,
                ))
            })?;
        let output = self
            .cloudtrail
            .lookup_events()
            .lookup_attributes(attribute)
            .start_time(AwsDateTime::from_secs(request.from))
            .end_time(AwsDateTime::from_secs(request.to))
            .max_results(20)
            .send()
            .await
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                    irmind_app::AdapterStorageError::CloudTrailLookupEventsFailed,
                ))
            })?;
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
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::CloudTrailResponseExceeds5MB,
            )));
        }
        Ok(raw)
    }

    fn identity_request<'a>(
        &self,
        call: &'a AuthorizedCall,
    ) -> Result<(&'a str, &'a str, &'a str), AppError> {
        if call.tool() != &Tool::CloudIdentity || call.arg("source") != Some(self.source_id()) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::WrongAWSIdentitySourceOrTool,
            )));
        }
        let account = call.arg("account").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingAWSAccount,
            ))
        })?;
        let kind = call.arg("kind").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingIAMIdentityKind,
            ))
        })?;
        let name = call.arg("name").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingIAMIdentityName,
            ))
        })?;
        if account.len() != 12
            || !account.bytes().all(|byte| byte.is_ascii_digit())
            || name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_+=,.@-".contains(&byte))
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidAWSIdentityRequest,
            )));
        }
        Ok((account, kind, name))
    }

    async fn identity_async(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        let (account, kind, name) = self.identity_request(call)?;
        self.verify_aws_identity(account).await?;
        let value = match kind {
            "role" => {
                let output = self
                    .iam
                    .get_role()
                    .role_name(name)
                    .send()
                    .await
                    .map_err(|_| {
                        AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                            irmind_app::AdapterStorageError::AWSIAMGetRoleFailed,
                        ))
                    })?;
                let role = output.role().ok_or({
                    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                        irmind_app::AdapterStorageError::AWSIAMRoleMissing,
                    ))
                })?;
                json!({"kind":"role","name":role.role_name(),"arn":role.arn(),"id":role.role_id()})
            }
            "user" => {
                let output = self
                    .iam
                    .get_user()
                    .user_name(name)
                    .send()
                    .await
                    .map_err(|_| {
                        AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                            irmind_app::AdapterStorageError::AWSIAMGetUserFailed,
                        ))
                    })?;
                let user = output.user().ok_or({
                    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                        irmind_app::AdapterStorageError::AWSIAMUserMissing,
                    ))
                })?;
                json!({"kind":"user","name":user.user_name(),"arn":user.arn(),"id":user.user_id()})
            }
            _ => {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::UnsupportedIAMIdentityKind,
                )));
            }
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
                    _ => Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(irmind_app::AdapterPolicyError::InvalidCloudTool))),
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
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::WrongCloudTrailSourceOrTool,
            )));
        }
        let account = call.arg("account").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingAWSAccount,
            ))
        })?;
        let event_name = call.arg("event_name").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingCloudTrailEventName,
            ))
        })?;
        let from = parse_utc(call.arg("from"))?;
        let to = parse_utc(call.arg("to"))?;
        if account.len() != 12
            || !account.bytes().all(|byte| byte.is_ascii_digit())
            || !safe_name(event_name, 128)
            || !(1..=86_400).contains(&(to - from))
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidBoundedCloudTrailRequest,
            )));
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
    let value = value.ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::MissingCloudTrailTime,
        ))
    })?;
    if value.len() != 20 || !value.ends_with('Z') {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::CloudTrailRequiresUTCSecondPrecision,
        )));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.timestamp())
        .map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidCloudTrailTime,
            ))
        })
}

fn safe_name(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

include!("tests.rs");
