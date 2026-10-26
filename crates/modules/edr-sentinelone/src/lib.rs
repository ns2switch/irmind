#![forbid(unsafe_code)]

use chrono::DateTime;
use irmind_app::{
    AppError, CancellationToken, EdrPort, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use std::time::Duration;

pub struct SentinelOne {
    async_client: reqwest::Client,
    base: Url,
    token: SecretString,
    source_id: String,
    site_id: String,
}

include!("manifest.rs");
impl Module for SentinelOne {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_edr(self)
    }
}

impl SentinelOne {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let setting = |name| config.required_value(name).map(str::to_owned);
        let base = Url::parse(&setting("IRMIND_SENTINELONE_URL")?).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSentinelOneURL,
            ))
        })?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::SentinelOneURLMustBeAnHTTPSOrigin,
            )));
        }
        let source_id = setting("IRMIND_SENTINELONE_SOURCE_ID")?;
        if !safe_id(&source_id) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSentinelOneSourceID,
            )));
        }
        let site_id = setting("IRMIND_SENTINELONE_SITE_ID")?;
        if !digits(&site_id) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSentinelOneSiteID,
            )));
        }
        let token = config
            .required_secret("IRMIND_SENTINELONE_API_TOKEN")?
            .expose_secret()
            .to_owned();
        if token.trim().is_empty() {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::EmptySentinelOneAPIToken,
            )));
        }
        let async_client = irmind_http::client_builder(Duration::from_secs(30), false)
            .build()
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                    irmind_app::AdapterStorageError::CannotCreateSentinelOneHTTPClient,
                ))
            })?;
        Ok(Self {
            async_client,
            base,
            token: SecretString::from(token),
            source_id,
            site_id,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, AppError> {
        self.base.join(path).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSentinelOneEndpoint,
            ))
        })
    }

    fn checked_call<'a>(&self, call: &'a AuthorizedCall, tool: &Tool) -> Result<&'a str, AppError> {
        if call.tool() != tool || call.arg("source") != Some(self.source_id()) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::WrongSentinelOneSourceOrTool,
            )));
        }
        let host = call.arg("host").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingHost,
            ))
        })?;
        if !safe_host(host) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSentinelOneHost,
            )));
        }
        Ok(host)
    }

    fn agent_id(agent: &Value) -> Result<&str, AppError> {
        agent["id"].as_str().filter(|id| digits(id)).ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::SentinelOneAgentHasNoValidID,
            ))
        })
    }

    async fn request_async(
        request: reqwest::RequestBuilder,
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = request.send() => result.map_err(|_| AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(irmind_app::AdapterStorageError::SentinelOneRequestFailed)))?,
        };
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "SentinelOne returned status {}",
                response.status()
            )));
        }
        let raw = irmind_http::read_limited(response, 5_000_000, cancel)
            .await
            .map_err(|error| match error {
                irmind_http::BodyError::Cancelled => AppError::Cancelled,
                irmind_http::BodyError::Transport => {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                        irmind_app::AdapterStorageError::SentinelOneResponseFailed,
                    ))
                }
                irmind_http::BodyError::TooLarge => {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                        irmind_app::AdapterPolicyError::SentinelOneResponseExceeds5MB,
                    ))
                }
            })?;
        serde_json::from_slice(&raw).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::InvalidSentinelOneJSON,
            ))
        })
    }

    async fn get_async(
        &self,
        path: &str,
        params: &[(&str, &str)],
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let url = self.endpoint(path)?;
        Self::request_async(
            self.async_client
                .get(url)
                .header(
                    "Authorization",
                    format!("ApiToken {}", self.token.expose_secret()),
                )
                .query(params),
            cancel,
        )
        .await
    }

    async fn agent_async(&self, host: &str, cancel: &CancellationToken) -> Result<Value, AppError> {
        let response = self
            .get_async(
                "/web/api/v2.1/agents",
                &[
                    ("siteIds", &self.site_id),
                    ("computerName", host),
                    ("limit", "2"),
                ],
                cancel,
            )
            .await?;
        select_agent(&response, host, &self.site_id)
    }
}

#[async_trait]
impl EdrPort for SentinelOne {
    fn source_id(&self) -> &str {
        &self.source_id
    }
    fn supports(&self, tool: &Tool) -> bool {
        matches!(
            tool,
            Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections
        )
    }
    fn process_tree_hint(&self) -> Option<&'static str> {
        Some("use threat_id:event_id from a threat's Explore process event")
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        match call.tool() {
            Tool::EdrHostInfo => self.host_info_async(call, cancel).await,
            Tool::EdrDetections => self.detections_async(call, cancel).await,
            Tool::EdrProcessTree => self.process_tree_async(call, cancel).await,
            _ => Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSentinelOneTool,
            ))),
        }
    }
}

impl SentinelOne {
    async fn host_info_async(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let host = self.checked_call(call, &Tool::EdrHostInfo)?;
        encode(&self.agent_async(host, cancel).await?)
    }

    async fn detections_async(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let host = self.checked_call(call, &Tool::EdrDetections)?;
        let (from, to) = window(call)?;
        let agent = self.agent_async(host, cancel).await?;
        let id = Self::agent_id(&agent)?;
        let response = self
            .get_async(
                "/web/api/v2.1/threats",
                &[
                    ("siteIds", &self.site_id),
                    ("agentIds", id),
                    ("createdAt__gte", from),
                    ("createdAt__lte", to),
                    ("limit", "20"),
                ],
                cancel,
            )
            .await?;
        validate_threats(&response, id, &self.site_id, from, to)?;
        encode(&response)
    }

    async fn process_tree_async(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let host = self.checked_call(call, &Tool::EdrProcessTree)?;
        let process_id = call.arg("process_id").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingProcessID,
            ))
        })?;
        let (threat_id, event_id) = process_id.split_once(':').ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::SentinelOneProcessIDMustBeThreatIdEventId,
            ))
        })?;
        if !digits(threat_id) || !safe_id(event_id) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSentinelOneProcessID,
            )));
        }
        let agent = self.agent_async(host, cancel).await?;
        let id = Self::agent_id(&agent)?;
        let threats = self
            .get_async(
                "/web/api/v2.1/threats",
                &[
                    ("siteIds", &self.site_id),
                    ("agentIds", id),
                    ("ids", threat_id),
                    ("limit", "2"),
                ],
                cancel,
            )
            .await?;
        let rows = data_array(&threats)?;
        if rows.len() != 1
            || rows[0]["id"].as_str() != Some(threat_id)
            || rows[0]["agentRealtimeInfo"]["agentId"].as_str() != Some(id)
            || rows[0]["agentRealtimeInfo"]["siteId"].as_str() != Some(&self.site_id)
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::SentinelOneThreatIsOutsideTheSelectedHost,
            )));
        }
        let path = format!("/web/api/v2.1/threats/{threat_id}/explore/events");
        let events = self
            .get_async(&path, &[("eventId", event_id), ("limit", "20")], cancel)
            .await?;
        if data_array(&events)?.len() > 20 {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::SentinelOneProcessTreeExceedsLimit,
            )));
        }
        encode(&events)
    }
}

include!("helpers.rs");
