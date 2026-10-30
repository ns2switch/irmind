#![forbid(unsafe_code)]

use chrono::DateTime;
use irmind_app::{
    AppError, CancellationToken, EdrPort, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::time::Duration;

pub struct CrowdStrike {
    async_client: reqwest::Client,
    base: Url,
    client_id: SecretString,
    client_secret: SecretString,
    source_id: String,
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "edr-crowdstrike",
    version: "0.1.0",
    ports: &[ModulePort::Edr],
    tools: &[Tool::EdrHostInfo, Tool::EdrDetections],
    config: &[
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_URL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_CA_PEM",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_CA_SHA256",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_CLIENT_ID",
            required: true,
            secret: true,
        },
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_CLIENT_SECRET",
            required: true,
            secret: true,
        },
    ],
};

impl Module for CrowdStrike {
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

impl CrowdStrike {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let setting = |name| config.required_value(name).map(str::to_owned);
        let base = Url::parse(&setting("IRMIND_CROWDSTRIKE_URL")?).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidCrowdStrikeURL,
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
                irmind_app::AdapterPolicyError::CrowdStrikeURLMustBeAnHTTPSOrigin,
            )));
        }
        let source_id = setting("IRMIND_CROWDSTRIKE_SOURCE_ID")?;
        if !safe_id(&source_id) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidCrowdStrikeSourceID,
            )));
        }
        let client_id = config
            .required_secret("IRMIND_CROWDSTRIKE_CLIENT_ID")?
            .expose_secret()
            .to_owned();
        let client_secret = config
            .required_secret("IRMIND_CROWDSTRIKE_CLIENT_SECRET")?
            .expose_secret()
            .to_owned();
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::EmptyCrowdStrikeCredential,
            )));
        }
        let async_client = irmind_http::client_builder_with_ca(
            Duration::from_secs(30),
            false,
            irmind_http::load_optional_ca(
                config.value("IRMIND_CROWDSTRIKE_CA_PEM"),
                config.value("IRMIND_CROWDSTRIKE_CA_SHA256"),
            )
            .map_err(|error| AppError::Policy(error.to_string()))?
            .as_ref(),
        )
        .build()
        .map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::CannotCreateCrowdStrikeHTTPClient,
            ))
        })?;
        Ok(Self {
            async_client,
            base,
            client_id: SecretString::from(client_id),
            client_secret: SecretString::from(client_secret),
            source_id,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, AppError> {
        self.base.join(path).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidCrowdStrikeEndpoint,
            ))
        })
    }

    fn checked_call<'a>(&self, call: &'a AuthorizedCall, tool: &Tool) -> Result<&'a str, AppError> {
        if call.tool() != tool || call.arg("source") != Some(self.source_id()) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::WrongCrowdStrikeSourceOrTool,
            )));
        }
        let host = call.arg("host").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingHost,
            ))
        })?;
        if !safe_host(host) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidCrowdStrikeHost,
            )));
        }
        Ok(host)
    }

    async fn request_async(
        request: reqwest::RequestBuilder,
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = request.send() => result.map_err(|_| AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(irmind_app::AdapterStorageError::CrowdStrikeRequestFailed)))?,
        };
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "CrowdStrike returned status {}",
                response.status()
            )));
        }
        let raw = irmind_http::read_limited(response, 5_000_000, cancel)
            .await
            .map_err(|error| match error {
                irmind_http::BodyError::Cancelled => AppError::Cancelled,
                irmind_http::BodyError::Transport => {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                        irmind_app::AdapterStorageError::CrowdStrikeResponseFailed,
                    ))
                }
                irmind_http::BodyError::TooLarge => {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                        irmind_app::AdapterPolicyError::CrowdStrikeResponseExceeds5MB,
                    ))
                }
            })?;
        serde_json::from_slice(&raw).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::InvalidCrowdStrikeJSON,
            ))
        })
    }

    async fn token_async(&self, cancel: &CancellationToken) -> Result<SecretString, AppError> {
        let url = self.endpoint("/oauth2/token")?;
        let response = Self::request_async(
            self.async_client.post(url).form(&[
                ("client_id", self.client_id.expose_secret()),
                ("client_secret", self.client_secret.expose_secret()),
            ]),
            cancel,
        )
        .await?;
        let token = response["access_token"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or({
                AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                    irmind_app::AdapterStorageError::CrowdStrikeTokenResponseIsInvalid,
                ))
            })?;
        Ok(SecretString::from(token.to_owned()))
    }

    async fn host_async(
        &self,
        host: &str,
        token: &SecretString,
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let url = self.endpoint("/devices/combined/devices/v1")?;
        let filter = format!("hostname:'{host}'");
        let response = Self::request_async(
            self.async_client
                .get(url)
                .bearer_auth(token.expose_secret())
                .query(&[("filter", filter.as_str()), ("limit", "2")]),
            cancel,
        )
        .await?;
        select_host(&response, host)
    }
}

#[async_trait]
impl EdrPort for CrowdStrike {
    fn source_id(&self) -> &str {
        &self.source_id
    }
    fn supports(&self, tool: &Tool) -> bool {
        matches!(tool, Tool::EdrHostInfo | Tool::EdrDetections)
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        match call.tool() {
            Tool::EdrHostInfo => {
                let host = self.checked_call(call, &Tool::EdrHostInfo)?;
                let token = self.token_async(cancel).await?;
                encode(&self.host_async(host, &token, cancel).await?)
            }
            Tool::EdrDetections => self.detections_async(call, cancel).await,
            Tool::EdrProcessTree => Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::CrowdStrikeProcessTreeUnavailable,
            ))),
            _ => Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidCrowdStrikeTool,
            ))),
        }
    }
}

impl CrowdStrike {
    async fn detections_async(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let host = self.checked_call(call, &Tool::EdrDetections)?;
        let (from, to) = window(call)?;
        let token = self.token_async(cancel).await?;
        let device = self.host_async(host, &token, cancel).await?;
        let aid = device["device_id"]
            .as_str()
            .filter(|id| safe_id(id))
            .ok_or({
                AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                    irmind_app::AdapterStorageError::CrowdStrikeHostHasNoValidDeviceID,
                ))
            })?;
        let filter =
            format!("agent_id:'{aid}'+created_timestamp:>='{from}'+created_timestamp:<='{to}'");
        let url = self.endpoint("/alerts/combined/alerts/v1")?;
        let response = Self::request_async(
            self.async_client
                .post(url)
                .bearer_auth(token.expose_secret())
                .json(&json!({"filter":filter,"limit":20})),
            cancel,
        )
        .await?;
        validate_alerts(&response, aid, from, to)?;
        encode(&response)
    }
}

fn resources(value: &Value) -> Result<&Vec<Value>, AppError> {
    value["resources"].as_array().ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::CrowdStrikeResponseHasNoResourcesArray,
        ))
    })
}
fn select_host(response: &Value, host: &str) -> Result<Value, AppError> {
    let rows = resources(response)?;
    if rows.len() != 1
        || rows[0]["hostname"]
            .as_str()
            .is_none_or(|actual| !actual.eq_ignore_ascii_case(host))
    {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::CrowdStrikeHostIsMissingOrAmbiguous,
        )));
    }
    Ok(rows[0].clone())
}
fn validate_alerts(response: &Value, aid: &str, from: &str, to: &str) -> Result<(), AppError> {
    for alert in resources(response)? {
        if alert["agent_id"].as_str() != Some(aid)
            || !within(alert["created_timestamp"].as_str(), from, to)
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::CrowdStrikeReturnedAnAlertOutsideTheHostOrWindow,
            )));
        }
    }
    Ok(())
}
fn encode(value: &Value) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(value).map_err(|_| {
        AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::CannotEncodeCrowdStrikeEvidence,
        ))
    })
}
fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}
fn safe_host(value: &str) -> bool {
    safe_id(value) && value.len() <= 253
}
fn window(call: &AuthorizedCall) -> Result<(&str, &str), AppError> {
    let from = call.arg("from").ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::MissingStartTime,
        ))
    })?;
    let to = call.arg("to").ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::MissingEndTime,
        ))
    })?;
    let start = DateTime::parse_from_rfc3339(from).map_err(|_| {
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::InvalidStartTime,
        ))
    })?;
    let end = DateTime::parse_from_rfc3339(to).map_err(|_| {
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::InvalidEndTime,
        ))
    })?;
    if !(1..=86_400).contains(&end.signed_duration_since(start).num_seconds()) {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::CrowdStrikeDetectionWindowMustBeAtMost24Hours,
        )));
    }
    Ok((from, to))
}
fn within(value: Option<&str>, from: &str, to: &str) -> bool {
    let Some(value) = value else { return false };
    let (Ok(value), Ok(from), Ok(to)) = (
        DateTime::parse_from_rfc3339(value),
        DateTime::parse_from_rfc3339(from),
        DateTime::parse_from_rfc3339(to),
    ) else {
        return false;
    };
    value >= from && value <= to
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::wildcard_imports)]
mod tests;
