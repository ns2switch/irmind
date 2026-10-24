#![forbid(unsafe_code)]

use irmind_app::{
    AppError, InternalIntelPort,
    modules::{ConfigField, Module, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::io::Read as _;

pub struct Misp {
    client: reqwest::blocking::Client,
    endpoint: reqwest::Url,
    key: SecretString,
    source_id: String,
}

static MANIFEST: ModuleManifest = ModuleManifest {
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

    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
        registry.add_internal_intel(self)
    }
}

impl Misp {
    pub fn from_env() -> Result<Self, AppError> {
        let setting = |name| {
            std::env::var(name)
                .map_err(|_| AppError::Policy(format!("{name} is required for MISP")))
        };
        let base = setting("IRMIND_MISP_URL")?;
        let url =
            reqwest::Url::parse(&base).map_err(|_| AppError::Policy("invalid MISP URL".into()))?;
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
            return Err(AppError::Policy(
                "MISP URL must be an HTTPS base path".into(),
            ));
        }
        let endpoint = url
            .join("attributes/restSearch")
            .map_err(|_| AppError::Policy("invalid MISP endpoint".into()))?;
        let source_id = setting("IRMIND_MISP_SOURCE_ID")?;
        if source_id.is_empty()
            || source_id.len() > 64
            || !source_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(AppError::Policy("invalid MISP source ID".into()));
        }
        let key = setting("IRMIND_MISP_API_KEY")?;
        if key.trim().is_empty() {
            return Err(AppError::Policy("empty MISP API key".into()));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| AppError::Storage(error.to_string()))?;
        Ok(Self {
            client,
            endpoint,
            key: SecretString::from(key),
            source_id,
        })
    }
}

impl InternalIntelPort for Misp {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn lookup(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::ThreatIntelInternal || call.arg("source") != Some(self.source_id())
        {
            return Err(AppError::Policy("wrong MISP source or tool".into()));
        }
        let ioc = call
            .arg("ioc")
            .ok_or_else(|| AppError::Policy("missing IOC".into()))?;
        let body = search_body(ioc)?;
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header("Authorization", self.key.expose_secret())
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .map_err(|error| AppError::Storage(format!("MISP request failed: {error}")))?;
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "MISP returned status {}",
                response.status()
            )));
        }
        let mut raw = Vec::new();
        response
            .by_ref()
            .take(5_000_001)
            .read_to_end(&mut raw)
            .map_err(|error| AppError::Storage(format!("MISP response failed: {error}")))?;
        if raw.len() > 5_000_000 {
            return Err(AppError::Policy("MISP response exceeds 5 MB".into()));
        }
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
        return Err(AppError::Policy("invalid MISP IOC".into()));
    }
    Ok(json!({"returnFormat":"json","value":ioc,"limit":20,"page":1}))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::search_body;

    #[test]
    fn search_is_exact_and_bounded() {
        let body = search_body("example.com").unwrap();
        assert_eq!(body["value"], "example.com");
        assert_eq!(body["limit"], 20);
        assert!(search_body("alice@example.com").is_err());
    }
}
