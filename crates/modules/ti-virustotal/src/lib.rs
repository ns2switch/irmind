#![forbid(unsafe_code)]

use irmind_app::{
    AppError, ThreatIntelPort,
    modules::{ConfigField, Module, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use secrecy::{ExposeSecret, SecretString};
use std::io::Read as _;
use std::net::Ipv4Addr;

pub struct VirusTotal {
    client: reqwest::blocking::Client,
    key: SecretString,
}

static MANIFEST: ModuleManifest = ModuleManifest {
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

    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
        registry.add_threat_intel(self)
    }
}

impl VirusTotal {
    pub fn from_env() -> Result<Self, AppError> {
        let key = std::env::var("VIRUSTOTAL_API_KEY")
            .map_err(|_| AppError::Policy("VIRUSTOTAL_API_KEY is required".into()))?;
        if key.trim().is_empty() {
            return Err(AppError::Policy("empty VirusTotal key".into()));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(Self {
            client,
            key: SecretString::from(key),
        })
    }
}

impl ThreatIntelPort for VirusTotal {
    fn lookup(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::ThreatIntelExternal {
            return Err(AppError::Policy("wrong tool for VirusTotal".into()));
        }
        let ioc = call
            .arg("ioc")
            .ok_or_else(|| AppError::Policy("missing IOC".into()))?;
        let collection = classify_ioc(ioc)?;
        let url = format!("https://www.virustotal.com/api/v3/{collection}/{ioc}");
        let mut response = self
            .client
            .get(url)
            .header("x-apikey", self.key.expose_secret())
            .send()
            .map_err(|e| AppError::Storage(format!("VirusTotal request failed: {e}")))?;
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "VirusTotal returned status {}",
                response.status()
            )));
        }
        let mut raw = Vec::new();
        response
            .by_ref()
            .take(5_000_001)
            .read_to_end(&mut raw)
            .map_err(|e| AppError::Storage(format!("VirusTotal response failed: {e}")))?;
        if raw.len() > 5_000_000 {
            return Err(AppError::Policy("VirusTotal response exceeds 5 MB".into()));
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
mod tests {
    use super::classify_ioc;

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
