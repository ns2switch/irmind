use irmind_app::source_mapping::{MappingError, SourceRecordV1};
use irmind_domain::{
    BoundedObservations, CommonField as F, CommonValue, EntityIdentityScope as S,
    EntityObservation, EntityRole as R, EventContextV1, ObservedEntity, ObservedEntityKind as K,
};
// At most 32 occurrence descriptors. Unlisted supported context remains available.
const OBSERVATIONS: &[(F, K, R)] = &[
    (F::SourceIp, K::Ip, R::Source),
    (F::DestinationIp, K::Ip, R::Destination),
    (F::SourceDomain, K::Domain, R::Source),
    (F::DestinationDomain, K::Domain, R::Destination),
    (F::UserName, K::User, R::Actor),
    (F::UserId, K::User, R::Actor),
    (F::UserTargetName, K::User, R::Target),
    (F::UserTargetId, K::User, R::Target),
    (F::UserEffectiveName, K::User, R::Actor),
    (F::UserEffectiveId, K::User, R::Actor),
    (F::SourceUserName, K::User, R::Source),
    (F::DestinationUserName, K::User, R::Destination),
    (F::ProcessPid, K::Process, R::Subject),
    (F::ProcessParentPid, K::Process, R::Parent),
    (F::FilePath, K::File, R::Subject),
    (F::FileName, K::File, R::Subject),
    (F::HostName, K::Host, R::Subject),
    (F::HostId, K::Host, R::Subject),
    (F::CloudAccountId, K::Account, R::Subject),
    (F::CloudProjectId, K::Project, R::Subject),
    (F::FileHashMd5, K::Hash, R::Subject),
    (F::FileHashSha1, K::Hash, R::Subject),
    (F::FileHashSha256, K::Hash, R::Subject),
    (F::ProcessHashSha256, K::Hash, R::Subject),
    (F::ProcessParentHashSha256, K::Hash, R::Subject),
    (F::RegistryPath, K::Registry, R::Subject),
    (F::DnsQuestionName, K::Domain, R::Related),
    (F::UrlDomain, K::Domain, R::Related),
];
pub(super) fn project(
    source: &SourceRecordV1,
    context: &EventContextV1,
) -> Result<BoundedObservations, MappingError> {
    let mut observations = Vec::new();
    for &(field, kind, role) in OBSERVATIONS {
        let Some(value) = context.get(field) else {
            continue;
        };
        let text = match value {
            CommonValue::Text(value) => value.as_str().to_owned(),
            CommonValue::Ip(value) => value.to_string(),
            CommonValue::Unsigned(value) => value.to_string(),
            CommonValue::Hash(value) => value.value().into(),
            _ => return Err(invalid()),
        };
        let scope = if matches!(kind, K::Ip | K::Domain | K::Hash) {
            S::Global
        } else if kind == K::User {
            user_scope(source, context, field)?
        } else {
            S::SourceRecord {
                source: source.origin().source().clone(),
                record: source.origin().record(),
            }
        };
        let entity = ObservedEntity::try_new(kind, &text, scope).map_err(|_| invalid())?;
        observations.push(EntityObservation::try_new(entity, role, field).map_err(|_| invalid())?);
    }
    BoundedObservations::try_new(observations).map_err(|_| invalid())
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}

// Directory account namespaces are explicit source values; no PID or clock is involved.
fn user_scope(
    source: &SourceRecordV1,
    context: &EventContextV1,
    field: F,
) -> Result<S, MappingError> {
    let domain = match field {
        F::UserTargetName | F::UserTargetId => F::UserTargetDomain,
        F::UserEffectiveName | F::UserEffectiveId => F::UserEffectiveDomain,
        F::SourceUserName => F::SourceUserDomain,
        F::DestinationUserName => F::DestinationUserDomain,
        _ => F::UserDomain,
    };
    let read = |field| match context.get(field) {
        Some(CommonValue::Text(text)) => text.as_str(),
        _ => "",
    };
    let realm = read(domain);
    let host = if read(F::HostId).is_empty() {
        read(F::HostName)
    } else {
        read(F::HostId)
    };
    let account = read(F::CloudAccountId);
    let source_namespace = if realm.is_empty() || (host.is_empty() && account.is_empty()) {
        source.origin().source().as_str()
    } else {
        ""
    };
    let mut material = b"irmind-ecs-user-namespace-v1\0".to_vec();
    let ordinal = source.origin().record().to_string();
    let record = if realm.is_empty() {
        ordinal.as_str()
    } else {
        ""
    };
    let flavor = if matches!(
        field,
        F::UserId | F::UserTargetId | F::UserEffectiveId | F::SourceUserId | F::DestinationUserId
    ) {
        "id"
    } else {
        "name"
    };
    for value in [
        read(F::CloudProvider),
        account,
        host,
        realm,
        source_namespace,
        record,
        flavor,
    ] {
        material.extend_from_slice(&(value.len() as u64).to_be_bytes());
        material.extend_from_slice(value.as_bytes());
    }
    let name = format!(
        "ecs-user-v1:sha256={}",
        irmind_app::hex(&irmind_app::sha256(&material))
    );
    Ok(S::Account(
        irmind_domain::EventText::identifier(&name).map_err(|_| invalid())?,
    ))
}
