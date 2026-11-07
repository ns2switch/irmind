use super::{EventSchemaError, EventText};
use crate::EvidenceHash;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ObservedEntityKind {
    Ip,
    Domain,
    Host,
    User,
    Process,
    File,
    Registry,
    Hash,
    Account,
    Project,
    Resource,
    IamRole,
    KeyId,
    Session,
    Flow,
    Event,
    Rule,
    CollectorArtifact,
}
impl ObservedEntityKind {
    pub const ALL: &'static [Self] = &[
        Self::Ip,
        Self::Domain,
        Self::Host,
        Self::User,
        Self::Process,
        Self::File,
        Self::Registry,
        Self::Hash,
        Self::Account,
        Self::Project,
        Self::Resource,
        Self::IamRole,
        Self::KeyId,
        Self::Session,
        Self::Flow,
        Self::Event,
        Self::Rule,
        Self::CollectorArtifact,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Host => "host",
            Self::User => "user",
            Self::Process => "process",
            Self::File => "file",
            Self::Registry => "registry",
            Self::Hash => "hash",
            Self::Account => "account",
            Self::Project => "project",
            Self::Resource => "resource",
            Self::IamRole => "role",
            Self::KeyId => "key",
            Self::Session => "session",
            Self::Flow => "flow",
            Self::Event => "event",
            Self::Rule => "rule",
            Self::CollectorArtifact => "artifact",
        }
    }
    pub fn parse(value: &str) -> Result<Self, EventSchemaError> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == value)
            .ok_or(EventSchemaError::UnknownCode)
    }
}

/// Identity scope prevents PID reuse and cross-account/user collisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntityIdentityScope {
    Global,
    Account(EventText),
    Host(EventText),
    SourceRecord {
        source: EvidenceHash,
        record: u64,
    },
    ProcessLifetime {
        host: EventText,
        lifetime: EventText,
    },
}
impl EntityIdentityScope {
    fn stable_key(&self) -> (&str, &str, &str, u64) {
        match self {
            Self::Global => ("global", "", "", 0),
            Self::Account(value) => ("account", value.as_str(), "", 0),
            Self::Host(value) => ("host", value.as_str(), "", 0),
            Self::SourceRecord { source, record } => {
                ("source_record", source.as_str(), "", *record)
            }
            Self::ProcessLifetime { host, lifetime } => {
                ("process_lifetime", host.as_str(), lifetime.as_str(), 0)
            }
        }
    }
    fn validate(&self, kind: ObservedEntityKind) -> Result<(), EventSchemaError> {
        match self {
            Self::Global
                if !matches!(
                    kind,
                    ObservedEntityKind::Ip | ObservedEntityKind::Domain | ObservedEntityKind::Hash
                ) =>
            {
                return Err(EventSchemaError::InvalidObservation);
            }
            Self::Host(_) | Self::Account(_) if kind == ObservedEntityKind::Process => {
                return Err(EventSchemaError::InvalidObservation);
            }
            Self::ProcessLifetime { .. } if kind != ObservedEntityKind::Process => {
                return Err(EventSchemaError::InvalidObservation);
            }
            _ => {}
        }
        let values = match self {
            Self::Global | Self::SourceRecord { .. } => [None, None],
            Self::Host(value) | Self::Account(value) => [Some(value), None],
            Self::ProcessLifetime { host, lifetime } => [Some(host), Some(lifetime)],
        };
        if values
            .into_iter()
            .flatten()
            .any(|text| EventText::identifier(text.as_str()).is_err())
        {
            return Err(EventSchemaError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedEntity {
    kind: ObservedEntityKind,
    value: EventText,
    scope: EntityIdentityScope,
}
impl ObservedEntity {
    pub fn try_new(
        kind: ObservedEntityKind,
        value: &str,
        scope: EntityIdentityScope,
    ) -> Result<Self, EventSchemaError> {
        scope.validate(kind)?;
        let canonical = match kind {
            ObservedEntityKind::Ip => value
                .parse::<std::net::IpAddr>()
                .map_err(|_| EventSchemaError::InvalidValue)?
                .to_string(),
            ObservedEntityKind::Hash => value.to_ascii_lowercase(),
            ObservedEntityKind::Domain => value
                .strip_suffix('.')
                .unwrap_or(value)
                .to_ascii_lowercase(),
            _ => value.to_owned(),
        };
        let value = EventText::identifier(&canonical)?;
        match kind {
            ObservedEntityKind::Ip => {
                value
                    .as_str()
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| EventSchemaError::InvalidValue)?;
            }
            ObservedEntityKind::Hash
                if !matches!(value.as_str().len(), 32 | 40 | 64)
                    || !value.as_str().bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                return Err(EventSchemaError::InvalidValue);
            }
            ObservedEntityKind::Domain if !valid_domain(value.as_str()) => {
                return Err(EventSchemaError::InvalidValue);
            }
            _ => {}
        }
        Ok(Self { kind, value, scope })
    }
    pub fn stable_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.kind
            .as_str()
            .cmp(other.kind.as_str())
            .then_with(|| self.value.as_str().cmp(other.value.as_str()))
            .then_with(|| self.scope.stable_key().cmp(&other.scope.stable_key()))
    }
    pub(super) fn json_bytes(&self) -> usize {
        let scope = match &self.scope {
            EntityIdentityScope::Global => 32,
            EntityIdentityScope::Account(value) | EntityIdentityScope::Host(value) => {
                64 + value.json_bytes()
            }
            EntityIdentityScope::SourceRecord { .. } => 128,
            EntityIdentityScope::ProcessLifetime { host, lifetime } => {
                96 + host.json_bytes() + lifetime.json_bytes()
            }
        };
        256 + self.value.json_bytes() + scope
    }
    pub const fn kind(&self) -> ObservedEntityKind {
        self.kind
    }
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
    pub const fn scope(&self) -> &EntityIdentityScope {
        &self.scope
    }
}
fn valid_domain(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
