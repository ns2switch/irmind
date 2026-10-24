#![forbid(unsafe_code)]

use chrono::DateTime;
use irmind_app::{
    AppError, SiemPort,
    modules::{ConfigField, Module, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use secrecy::{ExposeSecret, SecretString};
use std::io::Read as _;

pub struct Splunk {
    client: reqwest::blocking::Client,
    endpoint: reqwest::Url,
    token: SecretString,
    source_id: String,
    index: String,
    account_field: String,
}

static MANIFEST: ModuleManifest = ModuleManifest {
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

    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
        registry.add_siem(self)
    }
}

impl Splunk {
    pub fn from_env() -> Result<Self, AppError> {
        let setting = |name| {
            std::env::var(name)
                .map_err(|_| AppError::Policy(format!("{name} is required for Splunk")))
        };
        let base = setting("IRMIND_SPLUNK_URL")?;
        let parsed = reqwest::Url::parse(&base)
            .map_err(|_| AppError::Policy("invalid Splunk URL".into()))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(AppError::Policy(
                "Splunk URL must be an HTTPS origin".into(),
            ));
        }
        let endpoint = parsed
            .join("/services/search/v2/jobs/export")
            .map_err(|_| AppError::Policy("invalid Splunk endpoint".into()))?;
        let source_id = setting("IRMIND_SPLUNK_SOURCE_ID")?;
        let index = setting("IRMIND_SPLUNK_INDEX")?;
        let account_field = setting("IRMIND_SPLUNK_ACCOUNT_FIELD")?;
        if !safe_identifier(&source_id) || !safe_identifier(&index) || !safe_field(&account_field) {
            return Err(AppError::Policy(
                "invalid Splunk source, index or account field".into(),
            ));
        }
        let token = setting("IRMIND_SPLUNK_TOKEN")?;
        if token.trim().is_empty() {
            return Err(AppError::Policy("empty Splunk token".into()));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(45))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(Self {
            client,
            endpoint,
            token: SecretString::from(token),
            source_id,
            index,
            account_field,
        })
    }

    fn spl(&self, account: &str, term: &str) -> Result<String, AppError> {
        if !safe_identifier(account)
            || term.is_empty()
            || term.len() > 128
            || !term
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-:@/".contains(&byte))
        {
            return Err(AppError::Policy("invalid Splunk search term".into()));
        }
        Ok(format!(
            "search index={} {}=\"{}\" \"{}\" | head 20",
            self.index, self.account_field, account, term
        ))
    }
}

impl SiemPort for Splunk {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn dialect(&self) -> &'static str {
        "SPL restricted literal search"
    }

    fn search(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::SiemSearch || call.arg("source") != Some(self.source_id()) {
            return Err(AppError::Policy("wrong Splunk source or tool".into()));
        }
        let arg = |name| {
            call.arg(name)
                .ok_or_else(|| AppError::Policy(format!("missing {name}")))
        };
        let account = arg("account")?;
        let from = DateTime::parse_from_rfc3339(arg("from")?)
            .map_err(|_| AppError::Policy("invalid Splunk start time".into()))?;
        let to = DateTime::parse_from_rfc3339(arg("to")?)
            .map_err(|_| AppError::Policy("invalid Splunk end time".into()))?;
        let span = to.signed_duration_since(from).num_seconds();
        if !(1..=86_400).contains(&span) {
            return Err(AppError::Policy(
                "Splunk query window must be at most 24 hours".into(),
            ));
        }
        let spl = self.spl(account, arg("query")?)?;
        let earliest = from.timestamp().to_string();
        let latest = to.timestamp().to_string();
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(self.token.expose_secret())
            .form(&[
                ("search", spl.as_str()),
                ("earliest_time", earliest.as_str()),
                ("latest_time", latest.as_str()),
                ("output_mode", "json"),
                ("max_time", "30"),
            ])
            .send()
            .map_err(|e| AppError::Storage(format!("Splunk request failed: {e}")))?;
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "Splunk returned status {}",
                response.status()
            )));
        }
        let mut raw = Vec::new();
        response
            .by_ref()
            .take(5_000_001)
            .read_to_end(&mut raw)
            .map_err(|e| AppError::Storage(format!("Splunk response failed: {e}")))?;
        if raw.len() > 5_000_000 {
            return Err(AppError::Policy("Splunk response exceeds 5 MB".into()));
        }
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
    fn generated_spl_cannot_escape_literal_search() {
        let splunk = Splunk {
            client: reqwest::blocking::Client::new(),
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
