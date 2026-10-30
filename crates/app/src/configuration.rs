use crate::{
    AppError, FixedAppError, hex,
    modules::{ModuleManifest, ModulePort},
    sha256,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::{Host, Url};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentConfig {
    #[serde(default = "version_one")]
    pub version: u8,
    #[serde(default)]
    pub llm_module: Option<String>,
    #[serde(default)]
    pub policy_path: Option<String>,
    #[serde(default)]
    pub input_microusd_per_million: Option<u64>,
    #[serde(default)]
    pub output_microusd_per_million: Option<u64>,
    /// Presentation-only setting; omitted from the signed v1 representation when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mouse_capture: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
    /// Presentation-only setting; absence preserves the existing signed v1 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_last_case: Option<bool>,
    #[serde(default)]
    pub modules: BTreeMap<String, ProductSettings>,
}

#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConfigChange {
    SelectLlm(Option<String>),
    SetEnabled {
        module: String,
        enabled: bool,
    },
    SetValue {
        module: String,
        field: String,
        value: String,
    },
    SetCertificateAuthority {
        module: String,
        path_field: String,
        path: String,
        sha256: String,
    },
    SetResumeLastCase(bool),
    SetMouseCapture(bool),
    SetTheme(String),
}

pub trait ConfigurationStore: Send + Sync {
    fn load(&self) -> Result<PersistentConfig, AppError>;
    fn save(&self, config: &PersistentConfig) -> Result<(), AppError>;
}

const fn version_one() -> u8 {
    1
}

impl Default for PersistentConfig {
    fn default() -> Self {
        Self {
            version: 1,
            llm_module: None,
            policy_path: None,
            input_microusd_per_million: None,
            output_microusd_per_million: None,
            mouse_capture: None,
            theme: None,
            resume_last_case: None,
            modules: BTreeMap::new(),
        }
    }
}

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::PolicyInvalidPublicConfiguration)
}

fn mismatch() -> AppError {
    AppError::Fixed(FixedAppError::PolicyConfigurationAuditMismatch)
}

fn manifest<'a>(
    id: &str,
    manifests: &'a [&ModuleManifest],
) -> Result<&'a ModuleManifest, AppError> {
    manifests
        .iter()
        .copied()
        .find(|item| item.id == id)
        .ok_or_else(invalid)
}

impl PersistentConfig {
    pub fn validate(&self, manifests: &[&ModuleManifest]) -> Result<(), AppError> {
        if self.version != 1
            || self
                .theme
                .as_deref()
                .is_some_and(|theme| !matches!(theme, "auto" | "light" | "dark"))
            || self.modules.len() > 256
            || self.policy_path.as_ref().is_some_and(|path| {
                path.is_empty() || path.len() > 4096 || path.chars().any(disallowed_char)
            })
            || self.input_microusd_per_million.is_some()
                != self.output_microusd_per_million.is_some()
            || self
                .input_microusd_per_million
                .is_some_and(|price| price > 1_000_000_000_000)
            || self
                .output_microusd_per_million
                .is_some_and(|price| price > 1_000_000_000_000)
        {
            return Err(invalid());
        }
        if let Some(id) = &self.llm_module
            && !manifest(id, manifests)?.ports.contains(&ModulePort::Llm)
        {
            return Err(invalid());
        }
        for (id, settings) in &self.modules {
            let module = manifest(id, manifests)?;
            if module.ports.contains(&ModulePort::Llm) && settings.enabled {
                return Err(invalid());
            }
            if settings.values.len() > 32 {
                return Err(invalid());
            }
            for (name, value) in &settings.values {
                let field = module
                    .config
                    .iter()
                    .find(|field| field.name == name)
                    .ok_or_else(invalid)?;
                if field.secret || !valid_value(name, value) {
                    return Err(invalid());
                }
            }
            for (name, value) in &settings.values {
                if let Some(prefix) = name.strip_suffix("_CA_PEM") {
                    let digest_field = format!("{prefix}_CA_SHA256");
                    if value.is_empty()
                        || settings
                            .values
                            .get(&digest_field)
                            .is_none_or(|digest| !valid_hash(digest))
                    {
                        return Err(invalid());
                    }
                }
                if let Some(prefix) = name.strip_suffix("_CA_SHA256") {
                    let path_field = format!("{prefix}_CA_PEM");
                    if !valid_hash(value) || !settings.values.contains_key(&path_field) {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(())
    }

    pub fn changed(
        &self,
        change: ConfigChange,
        manifests: &[&ModuleManifest],
    ) -> Result<Self, AppError> {
        let mut next = self.clone();
        match change {
            ConfigChange::SelectLlm(id) => {
                if let Some(ref id) = id
                    && !manifest(id, manifests)?.ports.contains(&ModulePort::Llm)
                {
                    return Err(invalid());
                }
                next.llm_module = id;
            }
            ConfigChange::SetEnabled { module, enabled } => {
                if manifest(&module, manifests)?
                    .ports
                    .contains(&ModulePort::Llm)
                {
                    return Err(invalid());
                }
                next.modules.entry(module).or_default().enabled = enabled;
            }
            ConfigChange::SetValue {
                module,
                field,
                value,
            } => {
                if field.ends_with("_CA_PEM") || field.ends_with("_CA_SHA256") {
                    return Err(invalid());
                }
                let schema = manifest(&module, manifests)?;
                if !schema
                    .config
                    .iter()
                    .any(|item| item.name == field && !item.secret)
                {
                    return Err(invalid());
                }
                let values = &mut next.modules.entry(module).or_default().values;
                if value.is_empty() {
                    values.remove(&field);
                } else {
                    values.insert(field, value);
                }
            }
            ConfigChange::SetCertificateAuthority {
                module,
                path_field,
                path,
                sha256,
            } => set_ca_values(&mut next, manifests, module, path_field, path, sha256)?,
            ConfigChange::SetResumeLastCase(enabled) => next.resume_last_case = Some(enabled),
            ConfigChange::SetMouseCapture(enabled) => next.mouse_capture = Some(enabled),
            ConfigChange::SetTheme(theme) => next.theme = Some(theme),
        }
        next.validate(manifests)?;
        Ok(next)
    }

    pub(super) fn active_egress_changed(&self, next: &Self) -> bool {
        if next.llm_module.is_some()
            && (self.llm_module != next.llm_module
                || next
                    .llm_module
                    .as_ref()
                    .is_some_and(|id| self.modules.get(id) != next.modules.get(id)))
        {
            return true;
        }
        next.modules
            .iter()
            .any(|(id, settings)| settings.enabled && self.modules.get(id) != Some(settings))
    }

    pub(super) fn fingerprint(&self) -> Result<String, AppError> {
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        Ok(hex(&sha256(&bytes)))
    }
}

fn set_ca_values(
    next: &mut PersistentConfig,
    manifests: &[&ModuleManifest],
    module: String,
    path_field: String,
    path: String,
    sha256: String,
) -> Result<(), AppError> {
    let schema = manifest(&module, manifests)?;
    let Some(prefix) = path_field.strip_suffix("_CA_PEM") else {
        return Err(invalid());
    };
    let digest_field = format!("{prefix}_CA_SHA256");
    if !schema
        .config
        .iter()
        .any(|item| item.name == path_field && !item.secret)
        || !schema
            .config
            .iter()
            .any(|item| item.name == digest_field && !item.secret)
        || (!path.is_empty() && (!valid_value(&path_field, &path) || !valid_hash(&sha256)))
    {
        return Err(invalid());
    }
    let values = &mut next.modules.entry(module).or_default().values;
    if path.is_empty() {
        values.remove(&path_field);
        values.remove(&digest_field);
    } else {
        values.insert(path_field, path);
        values.insert(digest_field, sha256);
    }
    Ok(())
}

fn valid_value(name: &str, value: &str) -> bool {
    if value.is_empty()
        || value.len() > 1024
        || value.trim() != value
        || value.chars().any(disallowed_char)
    {
        return false;
    }
    if !name.ends_with("_URL") {
        return true;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let loopback = matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback());
    (url.scheme() == "https" || (url.scheme() == "http" && loopback))
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn disallowed_char(ch: char) -> bool {
    ch.is_control()
        || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

mod recovery;
pub use recovery::{ConfigDifference, ConfigurationInspection, ConfigurationReview};
mod session;

#[cfg(test)]
mod tests;
