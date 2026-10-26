#![forbid(unsafe_code)]

use chrono::DateTime;
use irmind_app::{
    AppError, CancellationToken, SiemPort, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, SplQueryClass, Tool, classify_spl_query};
use secrecy::{ExposeSecret, SecretString};

pub struct Splunk {
    async_client: reqwest::Client,
    endpoint: reqwest::Url,
    token: SecretString,
    source_id: String,
    index: String,
    account_field: String,
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "siem-splunk",
    version: "0.1.0",
    ports: &[ModulePort::Siem],
    tools: &[Tool::SiemSearch],
    config: &[
        ConfigField {
            name: "IRMIND_SPLUNK_URL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_INDEX",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_ACCOUNT_FIELD",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_TOKEN",
            required: true,
            secret: true,
        },
    ],
};

impl Module for Splunk {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_siem(self)
    }
}

impl Splunk {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let setting = |name| config.required_value(name).map(str::to_owned);
        let base = setting("IRMIND_SPLUNK_URL")?;
        let parsed = reqwest::Url::parse(&base).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSplunkURL,
            ))
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::SplunkURLMustBeAnHTTPSOrigin,
            )));
        }
        let endpoint = parsed
            .join("/services/search/v2/jobs/export")
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::InvalidSplunkEndpoint,
                ))
            })?;
        let source_id = setting("IRMIND_SPLUNK_SOURCE_ID")?;
        let index = setting("IRMIND_SPLUNK_INDEX")?;
        let account_field = setting("IRMIND_SPLUNK_ACCOUNT_FIELD")?;
        if !safe_identifier(&source_id) || !safe_identifier(&index) || !safe_field(&account_field) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSplunkSourceIndexOrAccountField,
            )));
        }
        let token = config
            .required_secret("IRMIND_SPLUNK_TOKEN")?
            .expose_secret()
            .to_owned();
        if token.trim().is_empty() {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::EmptySplunkToken,
            )));
        }
        let async_client = irmind_http::client_builder(std::time::Duration::from_secs(45), false)
            .build()
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                    irmind_app::AdapterStorageError::SplunkHTTPClientUnavailable,
                ))
            })?;
        Ok(Self {
            async_client,
            endpoint,
            token: SecretString::from(token),
            source_id,
            index,
            account_field,
        })
    }

    fn spl(&self, account: &str, term: &str) -> Result<String, AppError> {
        if !safe_identifier(account) || classify_spl_query(term) != SplQueryClass::SafeLiteral {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSplunkSearchTerm,
            )));
        }
        Ok(format!(
            "search index={} {}=\"{}\" \"{}\" | head 20",
            self.index, self.account_field, account, term
        ))
    }
}

#[async_trait]
impl SiemPort for Splunk {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn dialect(&self) -> &'static str {
        "SPL restricted literal search"
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::SiemSearch || call.arg("source") != Some(self.source_id()) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::WrongSplunkSourceOrTool,
            )));
        }
        let arg = |name| {
            call.arg(name)
                .ok_or_else(|| AppError::Policy(format!("missing {name}")))
        };
        let account = arg("account")?;
        let from = DateTime::parse_from_rfc3339(arg("from")?).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSplunkStartTime,
            ))
        })?;
        let to = DateTime::parse_from_rfc3339(arg("to")?).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSplunkEndTime,
            ))
        })?;
        if !(1..=86_400).contains(&to.signed_duration_since(from).num_seconds()) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::SplunkQueryWindowMustBeAtMost24Hours,
            )));
        }
        let spl = self.spl(account, arg("query")?)?;
        let earliest = from.timestamp().to_string();
        let latest = to.timestamp().to_string();
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = self.async_client.post(self.endpoint.clone())
                .bearer_auth(self.token.expose_secret())
                .form(&[("search", spl.as_str()),("earliest_time", earliest.as_str()),
                        ("latest_time", latest.as_str()),("output_mode", "json"),("max_time", "30")])
                .send() => result.map_err(|_| AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(irmind_app::AdapterStorageError::SplunkRequestFailed)))?,
        };
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "Splunk returned status {}",
                response.status()
            )));
        }
        let raw = irmind_http::read_limited(response, 5_000_000, cancel)
            .await
            .map_err(|error| match error {
                irmind_http::BodyError::Cancelled => AppError::Cancelled,
                irmind_http::BodyError::Transport => {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                        irmind_app::AdapterStorageError::SplunkResponseFailed,
                    ))
                }
                irmind_http::BodyError::TooLarge => {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                        irmind_app::AdapterPolicyError::SplunkResponseExceeds5MB,
                    ))
                }
            })?;
        Ok(raw)
    }
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn safe_field(value: &str) -> bool {
    safe_identifier(value) && !value.starts_with('.')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
        let port = Splunk {
            async_client: reqwest::Client::builder()
                .use_rustls_tls()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint: reqwest::Url::parse(&format!(
                "{}services/search/v2/jobs/export",
                server.origin()
            ))
            .unwrap(),
            token: SecretString::from("synthetic-token".to_owned()),
            source_id: "splunk-prod".into(),
            index: "cloudtrail".into(),
            account_field: "recipientAccountId".into(),
        };
        let requests =
            irmind_testkit::run_siem_recorded(&port, server, RESPONSE.as_bytes()).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert!(String::from_utf8_lossy(&requests[0].body).contains("AssumeRole"));
        assert!(String::from_utf8_lossy(&requests[0].body).contains("123456789012"));
    }

    #[test]
    fn generated_spl_cannot_escape_literal_search() {
        let splunk = Splunk {
            async_client: reqwest::Client::new(),
            endpoint: reqwest::Url::parse("https://splunk.example/services/search/v2/jobs/export")
                .unwrap(),
            token: SecretString::from("test".to_owned()),
            source_id: "splunk-prod".into(),
            index: "cloudtrail".into(),
            account_field: "recipientAccountId".into(),
        };
        assert_eq!(
            splunk.spl("123456789012", "AssumeRole").unwrap(),
            "search index=cloudtrail recipientAccountId=\"123456789012\" \"AssumeRole\" | head 20"
        );
        assert!(
            splunk
                .spl("123456789012", "foo | outputlookup bar")
                .is_err()
        );
        assert!(splunk.spl("123\" | sendemail", "AssumeRole").is_err());
    }
}
