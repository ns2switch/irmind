//! Effective SIEM configuration is signed case context, never a permission grant.
use crate::{AppError, AuditEventKind, AuditOrigin, Case, CaseScope, Engine, SignedEntry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiemScopeMode {
    EventAccount,
    Instance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiemSourceScope {
    source: String,
    module: String,
    mode: SiemScopeMode,
    project: Option<String>,
    resource: Option<String>,
    #[serde(with = "optional_hash")]
    configuration_sha256: Option<irmind_domain::EvidenceHash>,
}
impl SiemSourceScope {
    pub fn event_account(source: &str, module: &str) -> Result<Self, AppError> {
        let value = Self {
            source: source.into(),
            module: module.into(),
            mode: SiemScopeMode::EventAccount,
            project: None,
            resource: None,
            configuration_sha256: None,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn instance(
        source: &str,
        module: &str,
        project: &str,
        location: &str,
        instance: &str,
    ) -> Result<Self, AppError> {
        let value = Self {
            source: source.into(),
            module: module.into(),
            mode: SiemScopeMode::Instance,
            project: Some(project.into()),
            resource: Some(format!(
                "projects/{project}/locations/{location}/instances/{instance}"
            )),
            configuration_sha256: None,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn with_configuration_hash(mut self, hash: [u8; 32]) -> Self {
        self.configuration_sha256 = Some(irmind_domain::EvidenceHash::from_bytes(hash));
        self
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn module(&self) -> &str {
        &self.module
    }
    pub const fn mode(&self) -> SiemScopeMode {
        self.mode
    }
    pub fn project(&self) -> Option<&str> {
        self.project.as_deref()
    }
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        if !atom(&self.source, 128) || !atom(&self.module, 64) {
            return Err(invalid());
        }
        match (self.mode, self.project(), self.resource()) {
            (SiemScopeMode::EventAccount, None, None) => Ok(()),
            (SiemScopeMode::Instance, Some(project), Some(resource)) => {
                let parts = resource.split('/').collect::<Vec<_>>();
                if parts.len() == 6
                    && parts[0] == "projects"
                    && parts[1] == project
                    && parts[2] == "locations"
                    && parts[4] == "instances"
                    && [parts[1], parts[3], parts[5]]
                        .iter()
                        .all(|v| atom(v, 128) && !v.contains(['.', ':']))
                {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            _ => Err(invalid()),
        }
    }
}
fn atom(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}
fn invalid() -> AppError {
    AppError::Policy("invalid effective SIEM source scope record".into())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeSnapshot {
    detail: String,
    version: u8,
    case_scope: String,
    module_fingerprint: String,
    policy_fingerprint: String,
    sources: Vec<SiemSourceScope>,
}
impl ScopeSnapshot {
    fn validate(&self, current_scope: &str) -> Result<(), AppError> {
        let scope = CaseScope::parse(current_scope).map_err(|_| invalid())?;
        if self.detail != "effective-siem-source-scopes"
            || self.version != 1
            || self.case_scope != current_scope
            || self.sources.is_empty()
            || self.sources.len() > 64
            || !fingerprint(&self.module_fingerprint)
            || !fingerprint(&self.policy_fingerprint)
            || self
                .sources
                .windows(2)
                .any(|pair| pair[0].source >= pair[1].source)
        {
            return Err(invalid());
        }
        for source in &self.sources {
            source.validate()?;
            if !scope.allows_source(source.source()) {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn fingerprint(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn snapshot(entry: &SignedEntry) -> Result<Option<ScopeSnapshot>, AppError> {
    if entry.kind != AuditEventKind::ModulesActivated || !entry.payload.starts_with('{') {
        return Ok(None);
    }
    if entry.payload.len() > 65_536 {
        return Err(AppError::InvalidChain(entry.seq));
    }
    serde_json::from_str(&entry.payload)
        .map(Some)
        .map_err(|_| AppError::InvalidChain(entry.seq))
}
/// Called during case and export metadata verification, after signature checks.
pub(crate) fn verify_entry(entry: &SignedEntry, current_scope: &str) -> Result<(), AppError> {
    if let Some(value) = snapshot(entry)? {
        if entry.origin != AuditOrigin::System.as_str() {
            return Err(AppError::InvalidChain(entry.seq));
        }
        value
            .validate(current_scope)
            .map_err(|_| AppError::InvalidChain(entry.seq))?;
    }
    Ok(())
}
/// Retain historical instance-wide reads even after disabling a connector.
/// Callers must authenticate the chain before treating this context as trusted.
pub fn recorded_instance_sources(
    entries: &[SignedEntry],
) -> Result<Vec<SiemSourceScope>, AppError> {
    let mut sources = BTreeMap::new();
    for entry in entries {
        if let Some(value) = snapshot(entry)? {
            value
                .validate(&value.case_scope)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            for source in value.sources {
                if source.mode() == SiemScopeMode::Instance {
                    sources.insert(source.source.clone(), source);
                }
            }
        }
    }
    Ok(sources.into_values().collect())
}
impl Engine<'_> {
    pub(crate) fn validate_source_scope(
        &self,
        call: &crate::AuthorizedCall,
    ) -> Result<(), AppError> {
        let Some(source) = call.arg("source").and_then(|id| self.source_scopes.get(id)) else {
            return Ok(());
        };
        if source.mode() == SiemScopeMode::Instance {
            let ceiling = self.policy.scope.as_ref().ok_or_else(|| {
                AppError::Policy(
                    "Chronicle instance scope requires an explicit organization policy ceiling"
                        .into(),
                )
            })?;
            if !ceiling.allows_source(source.source()) || call.arg("account") != source.project() {
                return Err(AppError::Policy(
                    "outside configured Chronicle instance scope".into(),
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn record_source_scopes_unlocked(&self, case: &Case) -> Result<(), AppError> {
        if case.sealed {
            return Ok(());
        }
        let scope = CaseScope::parse(&case.scope).map_err(|_| invalid())?;
        let sources = self
            .source_scopes
            .values()
            .filter(|value| scope.allows_source(value.source()))
            .cloned()
            .collect::<Vec<_>>();
        if sources.is_empty() {
            return Ok(());
        }
        let snapshot = ScopeSnapshot {
            detail: "effective-siem-source-scopes".into(),
            version: 1,
            case_scope: case.scope.clone(),
            module_fingerprint: self.module_fingerprint.clone(),
            policy_fingerprint: self.policy_fingerprint.clone(),
            sources,
        };
        snapshot.validate(&case.scope)?;
        let payload = serde_json::to_string(&snapshot).map_err(|_| invalid())?;
        if payload.len() > 65_536 {
            return Err(invalid());
        }
        let entries = self.audit_log.entries(&case.id)?;
        for entry in entries.iter().rev() {
            if let Some(previous) = self::snapshot(entry)? {
                if previous == snapshot {
                    return Ok(());
                }
                break;
            }
        }
        self.audit(
            &case.id,
            AuditOrigin::System,
            AuditEventKind::ModulesActivated,
            &payload,
            None,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

mod optional_hash {
    use irmind_domain::EvidenceHash;
    use serde::{Deserialize, Serialize};
    pub(super) fn serialize<S: serde::Serializer>(
        hash: impl std::borrow::Borrow<Option<EvidenceHash>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        hash.borrow()
            .as_ref()
            .map(EvidenceHash::as_str)
            .serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EvidenceHash>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|v| {
                EvidenceHash::parse(&v)
                    .map_err(|_| serde::de::Error::custom("invalid configuration hash"))
            })
            .transpose()
    }
}
