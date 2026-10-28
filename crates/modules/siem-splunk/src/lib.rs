#![forbid(unsafe_code)]

use chrono::DateTime;
use irmind_app::{
    AppError, CancellationToken, SiemPort, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, SiemQuery, Tool};
mod query;
use query::SearchFields;
use secrecy::{ExposeSecret, SecretString};

pub struct Splunk {
    async_client: reqwest::Client,
    endpoint: reqwest::Url,
    token: SecretString,
    source_id: String,
    index: String,
    account_field: String,
    alert_id_field: String,
    search_fields: SearchFields,
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "siem-splunk",
    version: "0.1.0",
    ports: &[ModulePort::Siem],
    tools: &[Tool::SiemSearch, Tool::SiemGetAlert],
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
            name: "IRMIND_SPLUNK_ALERT_ID_FIELD",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_EVENT_NAME_FIELD",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_USER_FIELD",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_SOURCE_IP_FIELD",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_HOST_FIELD",
            required: false,
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
        let alert_id_field = config
            .value("IRMIND_SPLUNK_ALERT_ID_FIELD")
            .unwrap_or("alert_id");
        let search_fields = SearchFields::from_config(config);
        if !safe_identifier(&source_id)
            || !safe_identifier(&index)
            || !safe_field(&account_field)
            || !safe_field(alert_id_field)
            || !search_fields.valid()
        {
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
            alert_id_field: alert_id_field.to_owned(),
            search_fields,
        })
    }
}

#[async_trait]
impl SiemPort for Splunk {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn dialect(&self) -> &'static str {
        "SPL generated from structured fields"
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if !matches!(call.tool(), Tool::SiemSearch | Tool::SiemGetAlert)
            || call.arg("source") != Some(self.source_id())
        {
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
        let spl = match call.tool() {
            Tool::SiemSearch => {
                let query = SiemQuery::parse(call.proposal_args()).ok_or(AppError::Fixed(
                    irmind_app::FixedAppError::AdapterPolicy(
                        irmind_app::AdapterPolicyError::InvalidStructuredSplunkQuery,
                    ),
                ))?;
                self.spl_search(account, &query)?
            }
            Tool::SiemGetAlert => self.spl_alert(account, arg("alert_id")?)?,
            _ => {
                return Err(AppError::Fixed(
                    irmind_app::FixedAppError::PolicyInvalidRemoteTool,
                ));
            }
        };
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

fn safe_alert_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:@/".contains(&byte))
}

#[cfg(test)]
mod tests;
