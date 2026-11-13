use super::{AppError, invalid};
use irmind_domain::{
    CommonField, EntityIdentityScope, EntityObservation, EntityRole, EventText, EvidenceHash,
    ObservedEntity, ObservedEntityKind,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WireScope {
    Cluster {
        provider: String,
        id: String,
        namespace: Option<String>,
    },
    Global,
    Account {
        value: String,
    },
    Host {
        value: String,
    },
    SourceRecord {
        source: String,
        record: u64,
    },
    ProcessLifetime {
        host: String,
        lifetime: String,
    },
}
impl From<&EntityIdentityScope> for WireScope {
    fn from(scope: &EntityIdentityScope) -> Self {
        match scope {
            EntityIdentityScope::Cluster { cluster, namespace } => Self::Cluster {
                provider: cluster.provider().as_str().into(),
                id: cluster.id().into(),
                namespace: namespace.as_ref().map(|v| v.as_str().to_owned()),
            },
            EntityIdentityScope::Global => Self::Global,
            EntityIdentityScope::Account(v) => Self::Account {
                value: v.as_str().into(),
            },
            EntityIdentityScope::Host(v) => Self::Host {
                value: v.as_str().into(),
            },
            EntityIdentityScope::SourceRecord { source, record } => Self::SourceRecord {
                source: source.as_str().into(),
                record: *record,
            },
            EntityIdentityScope::ProcessLifetime { host, lifetime } => Self::ProcessLifetime {
                host: host.as_str().into(),
                lifetime: lifetime.as_str().into(),
            },
        }
    }
}
impl WireScope {
    fn checked(self) -> Result<EntityIdentityScope, AppError> {
        Ok(match self {
            Self::Cluster {
                provider,
                id,
                namespace,
            } => EntityIdentityScope::cluster(
                irmind_domain::ClusterIdentity::try_new(
                    irmind_domain::ClusterProvider::parse(&provider).map_err(|_| invalid())?,
                    &id,
                )
                .map_err(|_| invalid())?,
                namespace.as_deref(),
            )
            .map_err(|_| invalid())?,
            Self::Global => EntityIdentityScope::Global,
            Self::Account { value } => EntityIdentityScope::Account(identifier(&value)?),
            Self::Host { value } => EntityIdentityScope::Host(identifier(&value)?),
            Self::SourceRecord { source, record } => EntityIdentityScope::SourceRecord {
                source: EvidenceHash::parse(&source).map_err(|_| invalid())?,
                record,
            },
            Self::ProcessLifetime { host, lifetime } => EntityIdentityScope::ProcessLifetime {
                host: identifier(&host)?,
                lifetime: identifier(&lifetime)?,
            },
        })
    }
}
fn identifier(value: &str) -> Result<EventText, AppError> {
    EventText::identifier(value).map_err(|_| invalid())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireObservation {
    field: u16,
    kind: String,
    role: u16,
    #[serde(serialize_with = "serialize_scope")]
    scope: WireScope,
    value: String,
}
fn serialize_scope<S: serde::Serializer>(
    scope: &WireScope,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let value = serde_json::to_value(scope).map_err(serde::ser::Error::custom)?;
    super::ordered(value).serialize(serializer)
}
impl From<&EntityObservation> for WireObservation {
    fn from(value: &EntityObservation) -> Self {
        Self {
            kind: value.entity().kind().as_str().into(),
            value: value.entity().value().into(),
            scope: WireScope::from(value.entity().scope()),
            role: value.role().code(),
            field: value.field().code(),
        }
    }
}
impl WireObservation {
    pub(super) fn checked(self) -> Result<EntityObservation, AppError> {
        EntityObservation::try_new(
            ObservedEntity::try_new(
                ObservedEntityKind::parse(&self.kind).map_err(|_| invalid())?,
                &self.value,
                self.scope.checked()?,
            )
            .map_err(|_| invalid())?,
            EntityRole::from_code(self.role).map_err(|_| invalid())?,
            CommonField::from_code(self.field).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())
    }
}

pub(in crate::common_event) fn encode_scope(
    scope: &EntityIdentityScope,
) -> Result<String, AppError> {
    let value = serde_json::to_value(WireScope::from(scope)).map_err(|_| invalid())?;
    serde_json::to_string(&super::ordered(value)).map_err(|_| invalid())
}
pub(in crate::common_event) fn decode_scope(input: &str) -> Result<EntityIdentityScope, AppError> {
    if input.len() > 4096 {
        return Err(invalid());
    }
    let wire: WireScope = serde_json::from_str(input).map_err(|_| invalid())?;
    let scope = wire.checked()?;
    if encode_scope(&scope)? != input {
        return Err(invalid());
    }
    Ok(scope)
}
