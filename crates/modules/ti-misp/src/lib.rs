#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, InternalIntelPort, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

pub struct Misp {
    async_client: reqwest::Client,
    endpoint: reqwest::Url,
    key: SecretString,
    source_id: String,
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "ti-misp",
    version: "0.1.0",
    ports: &[ModulePort::InternalIntel],
    tools: &[Tool::ThreatIntelInternal],
    config: &[
        ConfigField {
            name: "IRMIND_MISP_URL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_MISP_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_MISP_API_KEY",
            required: true,
            secret: true,
        },
    ],
};

impl Module for Misp {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_internal_intel(self)
    }
}

impl Misp {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let setting = |name| config.required_value(name).map(str::to_owned);
        let base = setting("IRMIND_MISP_URL")?;
        let url = reqwest::Url::parse(&base).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidMISPURL,
            ))
        })?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().ends_with('/')
            || !url
                .path()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-/".contains(&byte))
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MISPURLMustBeAnHTTPSBasePath,
            )));
        }
        let endpoint = url.join("attributes/restSearch").map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidMISPEndpoint,
            ))
        })?;
        let source_id = setting("IRMIND_MISP_SOURCE_ID")?;
        if source_id.is_empty()
            || source_id.len() > 64
            || !source_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidMISPSourceID,
            )));
        }
        let key = config
            .required_secret("IRMIND_MISP_API_KEY")?
            .expose_secret()
            .to_owned();
        if key.trim().is_empty() {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::EmptyMISPAPIKey,
            )));
        }
        let async_client = irmind_http::client_builder(std::time::Duration::from_secs(30), false)
            .build()
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                    irmind_app::AdapterStorageError::MISPHTTPClientUnavailable,
                ))
            })?;
        Ok(Self {
            async_client,
            endpoint,
            key: SecretString::from(key),
            source_id,
        })
    }
}

#[async_trait]
impl InternalIntelPort for Misp {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::ThreatIntelInternal || call.arg("source") != Some(self.source_id())
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::WrongMISPSourceOrTool,
            )));
        }
        let ioc = call.arg("ioc").ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::MissingIOC,
            ))
        })?;
        let body = search_body(ioc)?;
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = self.async_client.post(self.endpoint.clone())
                .header("Authorization", self.key.expose_secret())
                .header("Accept", "application/json")
                .json(&body).send() => result.map_err(|_| AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(irmind_app::AdapterStorageError::MISPRequestFailed)))?,
        };
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "MISP returned status {}",
                response.status()
            )));
        }
        let raw = irmind_http::read_limited(response, 5_000_000, cancel)
            .await
            .map_err(|error| match error {
                irmind_http::BodyError::Cancelled => AppError::Cancelled,
                irmind_http::BodyError::Transport => {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                        irmind_app::AdapterStorageError::MISPResponseFailed,
                    ))
                }
                irmind_http::BodyError::TooLarge => {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                        irmind_app::AdapterPolicyError::MISPResponseExceeds5MB,
                    ))
                }
            })?;
        Ok(raw)
    }
}

fn search_body(ioc: &str) -> Result<Value, AppError> {
    if ioc.is_empty()
        || ioc.len() > 253
        || !ioc
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::InvalidMISPIOC,
        )));
    }
    Ok(json!({"returnFormat":"json","value":ioc,"limit":20,"page":1}))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn internal_intel_contract() {
        let mut config = ModuleConfig::new();
        config.insert_value("IRMIND_MISP_URL", "https://misp.invalid/".into());
        config.insert_value("IRMIND_MISP_SOURCE_ID", "misp-prod".into());
        config.insert_secret(
            "IRMIND_MISP_API_KEY",
            SecretString::from("test-key".to_owned()),
        );
        let port = Misp::from_config(&config).unwrap();
        irmind_testkit::run_internal_intel_contract(&port).unwrap();
        irmind_testkit::run_http_safety_contract().unwrap();
    }

    #[test]
    fn recorded_internal_intel_response_is_returned() {
        const RESPONSE: &str =
            "{\"response\":{\"Attribute\":[{\"type\":\"domain\",\"value\":\"example.org\"}]}}";
        let server =
            irmind_testkit::MockServer::start(vec![irmind_testkit::MockResponse::json(RESPONSE)])
                .unwrap();
        let port = Misp {
            async_client: reqwest::Client::builder()
                .use_rustls_tls()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint: reqwest::Url::parse(&format!("{}attributes/restSearch", server.origin()))
                .unwrap(),
            key: SecretString::from("synthetic-key".to_owned()),
            source_id: "misp-prod".into(),
        };
        let requests =
            irmind_testkit::run_internal_intel_recorded(&port, server, RESPONSE.as_bytes())
                .unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert!(String::from_utf8_lossy(&requests[0].body).contains("example.org"));
    }

    #[test]
    fn search_is_exact_and_bounded() {
        let body = search_body("example.com").unwrap();
        assert_eq!(body["value"], "example.com");
        assert_eq!(body["limit"], 20);
        assert!(search_body("alice@example.com").is_err());
    }
}
