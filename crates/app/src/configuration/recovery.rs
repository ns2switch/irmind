use super::{
    ConfigChange, ConfigurationStore, ModuleManifest, PersistentConfig, invalid, mismatch,
};
use crate::{AppError, Engine, FixedAppError, hex, sha256};
use std::collections::BTreeMap;

const SNAPSHOT_PREFIX: &str = "configuration-approved-v2:";
const LEGACY_PREFIX: &str = "configuration-approved:";
const MAX_CANONICAL_BYTES: usize = 65_536;

pub enum ConfigurationInspection {
    Current,
    Review(Box<ConfigurationReview>),
}

pub struct ConfigurationReview {
    pub approved: Option<PersistentConfig>,
    pub current: Option<PersistentConfig>,
    pub differences: Vec<ConfigDifference>,
    pub file_missing: bool,
    pub current_invalid: bool,
}

pub struct ConfigDifference {
    pub field: String,
    pub approved: Option<String>,
    pub current: Option<String>,
}

enum Approved {
    None,
    Legacy(String),
    Snapshot(PersistentConfig),
}

fn last_approved(engine: &Engine<'_>, manifests: &[&ModuleManifest]) -> Result<Approved, AppError> {
    engine.verify_global_operations()?;
    let entries = engine.audit_log.global_operations()?;
    let Some(entry) = entries.iter().rev().find(|entry| {
        entry.operation.starts_with(SNAPSHOT_PREFIX) || entry.operation.starts_with(LEGACY_PREFIX)
    }) else {
        return Ok(Approved::None);
    };
    if let Some(payload) = entry.operation.strip_prefix(SNAPSHOT_PREFIX) {
        return parse_snapshot(payload, manifests).map(Approved::Snapshot);
    }
    let fields = entry.operation.split(':').collect::<Vec<_>>();
    if fields.len() != 4
        || fields[0] != "configuration-approved"
        || !valid_hash(fields[1])
        || !valid_hash(fields[2])
        || !matches!(fields[3], "true" | "false")
    {
        return Err(mismatch());
    }
    Ok(Approved::Legacy(fields[2].into()))
}

fn parse_snapshot(
    payload: &str,
    manifests: &[&ModuleManifest],
) -> Result<PersistentConfig, AppError> {
    let fields = payload.split(':').collect::<Vec<_>>();
    if fields.len() != 4
        || !valid_hash(fields[0])
        || !valid_hash(fields[1])
        || !matches!(fields[2], "true" | "false")
        || fields[3].len() > MAX_CANONICAL_BYTES * 2
    {
        return Err(mismatch());
    }
    let bytes = hex::decode(fields[3]).map_err(|_| mismatch())?;
    let config: PersistentConfig = serde_json::from_slice(&bytes).map_err(|_| mismatch())?;
    config.validate(manifests)?;
    let canonical = serde_json::to_vec(&config).map_err(|_| mismatch())?;
    if bytes != canonical || hex(&sha256(&bytes)) != fields[1] {
        return Err(mismatch());
    }
    Ok(config)
}

fn snapshot_operation(
    old: &PersistentConfig,
    next: &PersistentConfig,
    egress: bool,
) -> Result<String, AppError> {
    let bytes = serde_json::to_vec(next).map_err(|_| invalid())?;
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(invalid());
    }
    Ok(format!(
        "{SNAPSHOT_PREFIX}{}:{}:{egress}:{}",
        old.fingerprint()?,
        hex(&sha256(&bytes)),
        hex::encode(bytes)
    ))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fields(config: &PersistentConfig) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert("version".into(), config.version.to_string());
    if let Some(value) = &config.llm_module {
        out.insert("llm_module".into(), value.clone());
    }
    if let Some(value) = &config.policy_path {
        out.insert("policy_path".into(), value.clone());
    }
    if let Some(value) = config.input_microusd_per_million {
        out.insert("input_microusd_per_million".into(), value.to_string());
    }
    if let Some(value) = config.output_microusd_per_million {
        out.insert("output_microusd_per_million".into(), value.to_string());
    }
    for (id, settings) in &config.modules {
        out.insert(
            format!("modules.{id}.enabled"),
            settings.enabled.to_string(),
        );
        for (name, value) in &settings.values {
            out.insert(format!("modules.{id}.{name}"), value.clone());
        }
    }
    out
}

fn differences(approved: &PersistentConfig, current: &PersistentConfig) -> Vec<ConfigDifference> {
    let old = fields(approved);
    let new = fields(current);
    old.keys()
        .chain(new.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter_map(|field| {
            let approved = old.get(field).cloned();
            let current = new.get(field).cloned();
            (approved != current).then(|| ConfigDifference {
                field: field.clone(),
                approved,
                current,
            })
        })
        .collect()
}

impl Engine<'_> {
    pub fn inspect_configuration(
        &self,
        store: &dyn ConfigurationStore,
        manifests: &[&ModuleManifest],
        file_present: bool,
    ) -> Result<ConfigurationInspection, AppError> {
        let approved = last_approved(self, manifests)?;
        let current = if file_present {
            store.load().ok()
        } else {
            None
        };
        let current = current.filter(|config| config.validate(manifests).is_ok());
        let matches = match (&approved, &current) {
            (Approved::None, None) if !file_present => true,
            (Approved::None, Some(config)) => *config == PersistentConfig::default(),
            (Approved::Legacy(hash), Some(config)) => config.fingerprint()? == *hash,
            (Approved::Snapshot(saved), Some(config)) => saved == config,
            _ => false,
        };
        if matches {
            return Ok(ConfigurationInspection::Current);
        }
        let saved = match approved {
            Approved::None => Some(PersistentConfig::default()),
            Approved::Legacy(_) => None,
            Approved::Snapshot(config) => Some(config),
        };
        let differences = saved
            .as_ref()
            .zip(current.as_ref())
            .map_or_else(Vec::new, |(old, new)| differences(old, new));
        Ok(ConfigurationInspection::Review(Box::new(
            ConfigurationReview {
                approved: saved,
                current: current.clone(),
                differences,
                file_missing: !file_present,
                current_invalid: file_present && current.is_none(),
            },
        )))
    }

    pub fn verify_configuration(
        &self,
        store: &dyn ConfigurationStore,
        manifests: &[&ModuleManifest],
    ) -> Result<(), AppError> {
        match self.inspect_configuration(store, manifests, true)? {
            ConfigurationInspection::Current => Ok(()),
            ConfigurationInspection::Review(_) => Err(mismatch()),
        }
    }

    pub fn restore_approved_configuration(
        &self,
        store: &dyn ConfigurationStore,
        manifests: &[&ModuleManifest],
        file_present: bool,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("restore approved configuration")?;
        let _lock = self.audit_log.lock_global_operations()?;
        let ConfigurationInspection::Review(review) =
            self.inspect_configuration(store, manifests, file_present)?
        else {
            return Err(mismatch());
        };
        let approved = review.approved.ok_or_else(mismatch)?;
        self.append_global_operation_unlocked(format!(
            "configuration-restored:{}",
            approved.fingerprint()?
        ))?;
        store.save(&approved)?;
        self.verify_configuration(store, manifests)
    }

    pub fn accept_current_configuration(
        &self,
        store: &dyn ConfigurationStore,
        manifests: &[&ModuleManifest],
        file_present: bool,
        confirmed: bool,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("accept current configuration")?;
        let _lock = self.audit_log.lock_global_operations()?;
        let ConfigurationInspection::Review(review) =
            self.inspect_configuration(store, manifests, file_present)?
        else {
            return Err(mismatch());
        };
        let current = review.current.ok_or_else(invalid)?;
        let approved = review.approved.unwrap_or_default();
        let egress = approved.active_egress_changed(&current) || review.file_missing;
        if egress && !confirmed {
            return Err(AppError::Fixed(
                FixedAppError::PolicyConfigurationConfirmationRequired,
            ));
        }
        self.append_global_operation_unlocked(snapshot_operation(&approved, &current, egress)?)?;
        store.save(&current)?;
        self.verify_configuration(store, manifests)
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
        self.append_global_operation_unlocked(snapshot_operation(&current, &next, egress)?)?;
        store.save(&next)?;
        if store.load()? != next {
            return Err(invalid());
        }
        Ok(true)
    }
}
