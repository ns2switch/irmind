use crate::{
    AppError, Engine, FixedAppError, hex,
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

#[derive(Clone, Eq, PartialEq)]
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
        }
        next.validate(manifests)?;
        Ok(next)
    }

    fn active_egress_changed(&self, next: &Self) -> bool {
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

    fn fingerprint(&self) -> Result<String, AppError> {
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        Ok(hex(&sha256(&bytes)))
    }
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

fn disallowed_char(ch: char) -> bool {
    ch.is_control()
        || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

impl Engine<'_> {
    pub fn verify_configuration(
        &self,
        store: &dyn ConfigurationStore,
        manifests: &[&ModuleManifest],
    ) -> Result<(), AppError> {
        let config = store.load()?;
        config.validate(manifests)?;
        self.verify_global_operations()?;
        let entries = self.audit_log.global_operations()?;
        let last = entries
            .iter()
            .rev()
            .find(|entry| entry.operation.starts_with("configuration-approved:"));
        match last {
            Some(entry) => {
                let mut fields = entry.operation.split(':');
                let valid = fields.next() == Some("configuration-approved")
                    && fields.next().is_some_and(valid_hash)
                    && fields.next() == Some(config.fingerprint()?.as_str())
                    && matches!(fields.next(), Some("true" | "false"))
                    && fields.next().is_none();
                if !valid {
                    return Err(mismatch());
                }
            }
            None if config != PersistentConfig::default() => return Err(mismatch()),
            None => {}
        }
        Ok(())
    }

    pub fn apply_configuration_change(
        &self,
        store: &dyn ConfigurationStore,
        manifests: &[&ModuleManifest],
        change: ConfigChange,
        confirmed: bool,
    ) -> Result<bool, AppError> {
        self.require_attended_analyst("change module configuration")?;
        let _lock = self.audit_log.lock_global_operations()?;
        self.verify_configuration(store, manifests)?;
        let current = store.load()?;
        let next = current.changed(change, manifests)?;
        if current == next {
            return Ok(false);
        }
        let egress = current.active_egress_changed(&next);
        if egress && !confirmed {
            return Err(AppError::Fixed(
                FixedAppError::PolicyConfigurationConfirmationRequired,
            ));
        }
        let operation = format!(
            "configuration-approved:{}:{}:{egress}",
            current.fingerprint()?,
            next.fingerprint()?
        );
        self.append_global_operation_unlocked(operation)?;
        store.save(&next)?;
        if store.load()? != next {
            return Err(invalid());
        }
        Ok(true)
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests;
