use super::{
    CommonField, EntityIdentityScope, EntityRole, EventOrigin, EventSchemaError, ObservedEntity,
};

/// A role describes one occurrence; it never creates another graph node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityObservation {
    entity: ObservedEntity,
    role: EntityRole,
    field: CommonField,
}
impl EntityObservation {
    pub fn try_new(
        entity: ObservedEntity,
        role: EntityRole,
        field: CommonField,
    ) -> Result<Self, EventSchemaError> {
        if !compatible(entity.kind().as_str(), role, field.as_str())
            || !kind_role(entity.kind(), role)
        {
            return Err(EventSchemaError::InvalidObservation);
        }
        Ok(Self {
            entity,
            role,
            field,
        })
    }
    pub const fn entity(&self) -> &ObservedEntity {
        &self.entity
    }
    pub const fn role(&self) -> EntityRole {
        self.role
    }
    pub const fn field(&self) -> CommonField {
        self.field
    }
}
fn kind_role(kind: super::ObservedEntityKind, role: EntityRole) -> bool {
    use super::ObservedEntityKind as K;
    use EntityRole as R;
    match kind {
        K::User | K::KubernetesUser | K::KubernetesServiceAccount => matches!(
            role,
            R::Actor | R::Target | R::Source | R::Destination | R::Observer | R::Related
        ),
        K::Ip | K::Domain | K::Host => matches!(
            role,
            R::Source | R::Destination | R::Target | R::Subject | R::Observer | R::Related
        ),
        K::Process => matches!(
            role,
            R::Subject | R::Parent | R::Actor | R::Target | R::Observer | R::Related
        ),
        K::File
        | K::Registry
        | K::Resource
        | K::KubernetesNamespace
        | K::KubernetesPod
        | K::KubernetesNode
        | K::Container
        | K::ContainerImage => {
            matches!(role, R::Subject | R::Target | R::Related | R::Observer)
        }
        K::Hash => matches!(role, R::Subject | R::Target | R::Related),
        K::Event => matches!(role, R::Subject | R::Related),
        K::Rule | K::CollectorArtifact => matches!(role, R::Subject | R::Observer | R::Related),
        K::Flow => matches!(role, R::Subject | R::Source | R::Destination | R::Related),
        K::Account | K::Project | K::IamRole | K::KeyId | K::Session => role != R::Parent,
    }
}
fn compatible(kind: &str, role: EntityRole, field: &str) -> bool {
    use CommonField as F;
    let Ok(field) = CommonField::parse(field) else {
        return false;
    };
    let expected = match field {
        F::SourceIp => ("ip", Some(EntityRole::Source)),
        F::DestinationIp => ("ip", Some(EntityRole::Destination)),
        F::SourceDomain => ("domain", Some(EntityRole::Source)),
        F::DestinationDomain => ("domain", Some(EntityRole::Destination)),
        F::DnsQuestionName | F::UrlDomain => ("domain", None),
        F::UserId | F::UserName | F::UserEffectiveId | F::UserEffectiveName => {
            ("user", Some(EntityRole::Actor))
        }
        F::UserTargetId | F::UserTargetName => ("user", Some(EntityRole::Target)),
        F::SourceUserId | F::SourceUserName => ("user", Some(EntityRole::Source)),
        F::DestinationUserId | F::DestinationUserName => ("user", Some(EntityRole::Destination)),
        F::ProcessEntityId | F::ProcessPid | F::ProcessName => {
            ("process", Some(EntityRole::Subject))
        }
        F::ProcessParentEntityId | F::ProcessParentPid | F::ProcessParentName => {
            ("process", Some(EntityRole::Parent))
        }
        F::FilePath | F::FileName => ("file", None),
        F::RegistryKey | F::RegistryPath | F::RegistryValue => ("registry", None),
        F::FileHashMd5
        | F::FileHashSha1
        | F::FileHashSha256
        | F::ProcessHashMd5
        | F::ProcessHashSha1
        | F::ProcessHashSha256
        | F::ProcessParentHashMd5
        | F::ProcessParentHashSha1
        | F::ProcessParentHashSha256 => ("hash", None),
        F::HostId | F::HostName | F::HostHostname => ("host", None),
        F::CloudAccountId => ("account", None),
        F::CloudProjectId => ("project", None),
        F::RuleId | F::RuleName => ("rule", None),
        F::IrmindResourceId => ("resource", None),
        F::IrmindIamRoleId => ("role", None),
        F::IrmindKeyId => ("key", None),
        F::IrmindSessionId => ("session", None),
        F::IrmindFlowRef => ("flow", None),
        F::IrmindSourceEventId => ("event", None),
        F::IrmindCollectorArtifact => ("artifact", None),
        F::IrmindKubernetesServiceAccount => ("k8s_service_account", None),
        F::OrchestratorNamespace => ("k8s_namespace", None),
        F::OrchestratorResourceName => {
            if !matches!(
                kind,
                "k8s_pod" | "k8s_node" | "k8s_namespace" | "k8s_service_account"
            ) {
                return false;
            }
            (kind, Some(EntityRole::Target))
        }
        F::IrmindKubernetesPod => ("k8s_pod", None),
        F::IrmindKubernetesNode => ("k8s_node", None),
        F::ContainerId => ("container", None),
        F::ContainerImageName => ("image", None),
        _ => return false,
    };
    let compatible_kind = kind == expected.0 || (kind == "k8s_user" && expected.0 == "user");
    compatible_kind && expected.1.is_none_or(|expected| role == expected)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BoundedObservations(Vec<EntityObservation>);
impl BoundedObservations {
    pub fn try_new(mut values: Vec<EntityObservation>) -> Result<Self, EventSchemaError> {
        if values.len() > 32 {
            return Err(EventSchemaError::LimitExceeded);
        }
        values.sort_by(|a, b| {
            a.entity
                .stable_cmp(&b.entity)
                .then_with(|| a.role.code().cmp(&b.role.code()))
                .then_with(|| a.field.code().cmp(&b.field.code()))
        });
        values.dedup();
        Ok(Self(values))
    }
    pub fn values(&self) -> &[EntityObservation] {
        &self.0
    }
    pub(super) fn validate_context(
        &self,
        context: &super::EventContextV1,
    ) -> Result<(), EventSchemaError> {
        for observation in &self.0 {
            if observation.field == CommonField::OrchestratorResourceName {
                let resource = match observation.entity.kind() {
                    super::ObservedEntityKind::KubernetesPod => "pods",
                    super::ObservedEntityKind::KubernetesNode => "nodes",
                    super::ObservedEntityKind::KubernetesNamespace => "namespaces",
                    super::ObservedEntityKind::KubernetesServiceAccount => "serviceaccounts",
                    _ => return Err(EventSchemaError::InvalidObservation),
                };
                if !matches!(context.get(CommonField::OrchestratorResourceType), Some(super::CommonValue::Text(value)) if value.as_str() == resource)
                {
                    return Err(EventSchemaError::InvalidObservation);
                }
            }
            if let EntityIdentityScope::Cluster { cluster, .. } = observation.entity.scope() {
                let Some(super::CommonValue::Text(value)) =
                    context.get(CommonField::IrmindClusterIdentity)
                else {
                    return Err(EventSchemaError::InvalidObservation);
                };
                if !cluster.matches_qualified(value.as_str()) {
                    return Err(EventSchemaError::InvalidObservation);
                }
            }
            let field = context
                .get(observation.field)
                .ok_or(EventSchemaError::InvalidObservation)?;
            let equal = match field {
                super::CommonValue::Text(value)
                    if observation.entity.kind() == super::ObservedEntityKind::Domain =>
                {
                    value
                        .as_str()
                        .strip_suffix('.')
                        .unwrap_or(value.as_str())
                        .to_ascii_lowercase()
                        == observation.entity.value()
                }
                super::CommonValue::Text(value) => value.as_str() == observation.entity.value(),
                super::CommonValue::Ip(value) => value.to_string() == observation.entity.value(),
                super::CommonValue::Unsigned(value) => {
                    value.to_string() == observation.entity.value()
                }
                super::CommonValue::Hash(value) => value.value() == observation.entity.value(),
                _ => false,
            };
            if !equal {
                return Err(EventSchemaError::InvalidObservation);
            }
        }
        Ok(())
    }
    pub(super) fn json_bytes(&self) -> usize {
        2 + self
            .0
            .iter()
            .map(|value| 128 + value.entity.json_bytes())
            .sum::<usize>()
    }
    pub(super) fn validate_origin(&self, origin: &EventOrigin) -> Result<(), EventSchemaError> {
        for value in &self.0 {
            if let EntityIdentityScope::SourceRecord { source, record } = value.entity.scope()
                && (source != origin.source() || *record != origin.record())
            {
                return Err(EventSchemaError::InvalidOrigin);
            }
        }
        Ok(())
    }
}
