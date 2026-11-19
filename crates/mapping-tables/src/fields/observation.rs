use super::{
    super::{
        definition::{Observation, Scope},
        invalid,
    },
    path,
};
use irmind_app::source_mapping::{MappingError, SourcePath, SourceRecordV1};
use irmind_domain::{
    CommonField, CommonValue, EntityIdentityScope, EntityObservation, EntityRole, EventText,
    EvidenceHash, ObservedEntity, ObservedEntityKind,
};

pub(crate) struct CompiledObservation {
    kind: ObservedEntityKind,
    role: EntityRole,
    scope: CompiledScope,
    conditions: Vec<irmind_app::source_mapping::SelectorCondition>,
}
enum CompiledScope {
    Global,
    SourceRecord,
    Host(SourcePath),
    Account(SourcePath),
    ProviderProcess {
        provider: irmind_domain::ProcessIdentityProvider,
        tenant: SourcePath,
        host: SourcePath,
    },
    ProcessLifetime {
        host: SourcePath,
        lifetime: SourcePath,
    },
    Cluster {
        namespace: Option<SourcePath>,
        principal: Option<SourcePath>,
    },
}
impl CompiledObservation {
    pub(super) fn compile(value: Observation, target: CommonField) -> Result<Self, MappingError> {
        if value.when.len() > 8 {
            return Err(MappingError::InvalidDefinition);
        }
        let result = Self {
            conditions: value
                .when
                .iter()
                .map(super::super::compile::condition)
                .collect::<Result<_, _>>()?,
            kind: ObservedEntityKind::parse(&value.kind).map_err(invalid)?,
            role: EntityRole::parse(&value.role).map_err(invalid)?,
            scope: CompiledScope::compile(value.scope)?,
        };
        let dummy = if matches!(&result.scope, CompiledScope::ProviderProcess { .. }) {
            "1"
        } else {
            match result.kind {
                ObservedEntityKind::Ip => "203.0.113.1",
                ObservedEntityKind::Domain => "example.test",
                ObservedEntityKind::Hash => "00000000000000000000000000000000",
                _ => "synthetic",
            }
        };
        let scope = match &result.scope {
            CompiledScope::Cluster {
                namespace,
                principal,
            } => EntityIdentityScope::cluster(
                irmind_domain::ClusterIdentity::try_new(
                    irmind_domain::ClusterProvider::Kubernetes,
                    "urn:k8s:validation",
                )
                .map_err(invalid)?,
                if namespace.is_some() || principal.is_some() {
                    Some("synthetic")
                } else {
                    None
                },
            )
            .map_err(invalid)?,
            CompiledScope::ProviderProcess { provider, .. } => {
                EntityIdentityScope::provider_process(
                    *provider,
                    "00000000000000000000000000000001",
                    "00000000000000000000000000000100",
                )
                .map_err(invalid)?
            }
            CompiledScope::ProcessLifetime { .. } => EntityIdentityScope::ProcessLifetime {
                host: EventText::identifier("host").map_err(invalid)?,
                lifetime: EventText::identifier("lifetime").map_err(invalid)?,
            },
            CompiledScope::Global => EntityIdentityScope::Global,
            CompiledScope::SourceRecord => EntityIdentityScope::SourceRecord {
                source: EvidenceHash::from_bytes([0; 32]),
                record: 0,
            },
            CompiledScope::Host(_) => {
                EntityIdentityScope::Host(EventText::identifier("host").map_err(invalid)?)
            }
            CompiledScope::Account(_) => {
                EntityIdentityScope::Account(EventText::identifier("account").map_err(invalid)?)
            }
        };
        EntityObservation::try_new(
            ObservedEntity::try_new(result.kind, dummy, scope).map_err(invalid)?,
            result.role,
            target,
        )
        .map_err(invalid)?;
        Ok(result)
    }
    pub(crate) fn applies(&self, source: &SourceRecordV1) -> bool {
        self.conditions
            .iter()
            .all(|c| c.predicate.matches(c.path.resolve(source.fields())))
    }
    pub(crate) fn project(
        &self,
        source: &SourceRecordV1,
        field: CommonField,
        value: &CommonValue,
    ) -> Result<EntityObservation, MappingError> {
        let bad = || MappingError::UnsupportedSourceValue;
        let text = match value {
            CommonValue::Text(v) => v.as_str().to_owned(),
            CommonValue::Unsigned(v) => v.to_string(),
            CommonValue::Ip(v) => v.to_string(),
            CommonValue::Hash(v) => v.value().into(),
            _ => return Err(bad()),
        };
        let named = |p: &SourcePath| {
            EventText::identifier(
                p.resolve(source.fields())
                    .and_then(irmind_app::source_mapping::SourceValue::as_text)
                    .ok_or_else(bad)?,
            )
            .map_err(|_| bad())
        };
        let scope = match &self.scope {
            CompiledScope::Cluster {
                namespace,
                principal,
            } => {
                let cluster = source.cluster_identity().ok_or_else(bad)?.clone();
                let explicit = namespace.as_ref().map(named).transpose()?;
                let account = principal.as_ref().map(named).transpose()?;
                let namespace = if let Some(account) = &account {
                    Some(super::service_account_parts(account.as_str())?.0)
                } else {
                    explicit.as_ref().map(EventText::as_str)
                };
                EntityIdentityScope::cluster(cluster, namespace).map_err(|_| bad())?
            }
            CompiledScope::Global => EntityIdentityScope::Global,
            CompiledScope::SourceRecord => EntityIdentityScope::SourceRecord {
                source: source.origin().source().clone(),
                record: source.origin().record(),
            },
            CompiledScope::Host(p) => EntityIdentityScope::Host(named(p)?),
            CompiledScope::Account(p) => EntityIdentityScope::Account(named(p)?),
            CompiledScope::ProviderProcess {
                provider,
                tenant,
                host,
            } => EntityIdentityScope::provider_process(
                *provider,
                named(tenant)?.as_str(),
                named(host)?.as_str(),
            )
            .map_err(|_| bad())?,
            CompiledScope::ProcessLifetime { host, lifetime } => {
                EntityIdentityScope::ProcessLifetime {
                    host: named(host)?,
                    lifetime: named(lifetime)?,
                }
            }
        };
        EntityObservation::try_new(
            ObservedEntity::try_new(self.kind, &text, scope).map_err(|_| bad())?,
            self.role,
            field,
        )
        .map_err(|_| bad())
    }
}

impl CompiledScope {
    fn compile(value: Scope) -> Result<Self, MappingError> {
        Ok(match value {
            Scope::Global => CompiledScope::Global,
            Scope::SourceRecord => CompiledScope::SourceRecord,
            Scope::Host(keys) => CompiledScope::Host(path(&keys)?),
            Scope::Account(keys) => CompiledScope::Account(path(&keys)?),
            Scope::Cluster {
                namespace,
                service_account_principal,
            } => {
                if namespace.is_some() && service_account_principal.is_some() {
                    return Err(MappingError::InvalidDefinition);
                }
                CompiledScope::Cluster {
                    namespace: namespace.as_deref().map(path).transpose()?,
                    principal: service_account_principal.as_deref().map(path).transpose()?,
                }
            }
            Scope::ProviderProcess {
                provider,
                tenant,
                host,
            } => CompiledScope::ProviderProcess {
                provider: irmind_domain::ProcessIdentityProvider::parse(&provider)
                    .map_err(invalid)?,
                tenant: path(&tenant)?,
                host: path(&host)?,
            },
            Scope::ProcessLifetime { host, lifetime } => CompiledScope::ProcessLifetime {
                host: path(&host)?,
                lifetime: path(&lifetime)?,
            },
        })
    }
}
