#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, ThreatIntelPort, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use secrecy::{ExposeSecret, SecretString};
use std::net::Ipv4Addr;

pub struct VirusTotal {
    async_client: reqwest::Client,
    api_base: reqwest::Url,
    key: SecretString,
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "ti-virustotal",
    version: "0.1.0",
    ports: &[ModulePort::ThreatIntel],
    tools: &[Tool::ThreatIntelExternal],
    config: &[ConfigField {
        name: "VIRUSTOTAL_API_KEY",
        required: true,
        secret: true,
    }],
};

impl Module for VirusTotal {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_threat_intel(self)
    }
}

impl VirusTotal {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let key = config
            .required_secret("VIRUSTOTAL_API_KEY")?
            .expose_secret()
            .to_owned();
        if key.trim().is_empty() {
            return Err(AppError::Policy("empty VirusTotal key".into()));
        }
        let async_client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AppError::Storage("VirusTotal HTTP client unavailable".into()))?;
        Ok(Self {
            async_client,
            api_base: reqwest::Url::parse("https://www.virustotal.com/api/v3/")
                .map_err(|_| AppError::Storage("invalid fixed VirusTotal endpoint".into()))?,
            key: SecretString::from(key),
        })
    }
}

#[async_trait]
impl ThreatIntelPort for VirusTotal {
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::ThreatIntelExternal {
            return Err(AppError::Policy("wrong tool for VirusTotal".into()));
        }
        let ioc = call
            .arg("ioc")
            .ok_or_else(|| AppError::Policy("missing IOC".into()))?;
        let collection = classify_ioc(ioc)?;
        let url = self
            .api_base
            .join(&format!("{collection}/{ioc}"))
            .map_err(|_| AppError::Policy("invalid VirusTotal path".into()))?;
        let mut response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = self.async_client.get(url).header("x-apikey", self.key.expose_secret()).send()
                => result.map_err(|_| AppError::Storage("VirusTotal request failed".into()))?,
        };
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "VirusTotal returned status {}",
                response.status()
            )));
        }
        let mut raw = Vec::new();
        loop {
            let chunk = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(AppError::Cancelled),
                result = response.chunk() => result.map_err(|_| AppError::Storage("VirusTotal response failed".into()))?,
            };
            let Some(chunk) = chunk else {
                break;
            };
            if raw.len().saturating_add(chunk.len()) > 5_000_000 {
                return Err(AppError::Policy("VirusTotal response exceeds 5 MB".into()));
            }
            raw.extend_from_slice(&chunk);
        }
        Ok(raw)
    }
}

fn classify_ioc(ioc: &str) -> Result<&'static str, AppError> {
    if matches!(ioc.len(), 32 | 40 | 64) && ioc.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok("files");
    }
    if let Ok(ip) = ioc.parse::<Ipv4Addr>() {
        let octets = ip.octets();
        let reserved = ip.is_private()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_broadcast()
            || ip.is_documentation()
            || ip.is_multicast()
            || ip.is_unspecified()
            || octets[0] >= 224
            || octets[0] == 0
            || (octets[0] == 100 && (64..=127).contains(&octets[1]))
            || (octets[0] == 198 && (18..=19).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
            || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99);
        if reserved {
            return Err(AppError::Policy(
                "non-public IP cannot be sent externally".into(),
            ));
        }
        return Ok("ip_addresses");
    }
    if !ioc.is_ascii() || ioc.len() > 253 || !ioc.contains('.') {
        return Err(AppError::Policy("unsupported or private IOC".into()));
    }
    let labels = ioc.split('.').collect::<Vec<_>>();
    let tld = labels.last().copied().unwrap_or_default();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) || tld.len() < 2
        || !tld.bytes().all(|byte| byte.is_ascii_alphabetic())
        || matches!(
            tld.to_ascii_lowercase().as_str(),
            "local" | "internal" | "localhost" | "invalid" | "test" | "example" | "onion"
        )
    {
        return Err(AppError::Policy("unsupported or private IOC".into()));
    }
    Ok("domains")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn threat_intel_contract() {
        let mut config = ModuleConfig::new();
        config.insert_secret(
            "VIRUSTOTAL_API_KEY",
            SecretString::from("test-key".to_owned()),
        );
        let port = VirusTotal::from_config(&config).unwrap();
        irmind_testkit::run_threat_intel_contract(&port).unwrap();
    }

    #[test]
    fn recorded_external_intel_response_is_returned() {
        const RESPONSE: &str = "{\"data\":{\"id\":\"example.org\",\"type\":\"domain\",\"attributes\":{\"reputation\":5}}}";
        let server =
            irmind_testkit::MockServer::start(vec![irmind_testkit::MockResponse::json(RESPONSE)])
                .unwrap();
        let port = VirusTotal {
            async_client: reqwest::Client::builder()
                .use_rustls_tls()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            api_base: reqwest::Url::parse(&format!("{}api/v3/", server.origin())).unwrap(),
            key: SecretString::from("synthetic-key".to_owned()),
        };
        let requests =
            irmind_testkit::run_threat_intel_recorded(&port, server, RESPONSE.as_bytes()).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].target, "/api/v3/domains/example.org");
    }

    #[test]
    fn only_public_bounded_iocs_reach_the_external_path() {
        assert_eq!(classify_ioc("8.8.8.8").ok(), Some("ip_addresses"));
        assert_eq!(classify_ioc("example.com").ok(), Some("domains"));
        assert_eq!(classify_ioc(&"a".repeat(64)).ok(), Some("files"));
        for ioc in [
            "10.0.0.1",
            "192.168.1.2",
            "100.64.0.1",
            "203.0.113.8",
            "alice@example.com",
            "corp.local",
            "http://example.com",
            "[::1]",
        ] {
            assert!(classify_ioc(ioc).is_err(), "{ioc}");
        }
    }
}
