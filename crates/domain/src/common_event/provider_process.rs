use super::{EntityIdentityScope, EventSchemaError, EventText};

/// A documented opaque process identifier namespace, never an OS PID lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessIdentityProvider {
    CrowdStrikeFdr,
}
impl ProcessIdentityProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CrowdStrikeFdr => "crowdstrike-fdr",
        }
    }
    pub fn parse(value: &str) -> Result<Self, EventSchemaError> {
        match value {
            "crowdstrike-fdr" => Ok(Self::CrowdStrikeFdr),
            _ => Err(EventSchemaError::InvalidObservation),
        }
    }
}
impl EntityIdentityScope {
    pub fn provider_process(
        provider: ProcessIdentityProvider,
        tenant: &str,
        host: &str,
    ) -> Result<Self, EventSchemaError> {
        if !valid_id(tenant) || !valid_id(host) {
            return Err(EventSchemaError::InvalidObservation);
        }
        Ok(Self::ProviderProcess {
            provider,
            tenant: EventText::identifier(tenant)?,
            host: EventText::identifier(host)?,
        })
    }
}
pub(super) fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
pub(super) fn canonical_id(value: &str) -> bool {
    value.len() <= 20
        && !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && value
            .parse::<u64>()
            .is_ok_and(|v| v != 0 && v.to_string() == value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{CommonField, EntityObservation, EntityRole, ObservedEntity, ObservedEntityKind};
    const TENANT: &str = "00000000000000000000000000000001";
    const HOST: &str = "00000000000000000000000000000100";
    fn scope(tenant: &str, host: &str) -> EntityIdentityScope {
        EntityIdentityScope::provider_process(ProcessIdentityProvider::CrowdStrikeFdr, tenant, host)
            .unwrap()
    }
    #[test]
    fn provider_process_scope_separates_tenants_hosts_and_other_scopes() {
        let entity =
            |scope| ObservedEntity::try_new(ObservedEntityKind::Process, "42", scope).unwrap();
        let current = entity(scope(TENANT, HOST));
        assert_ne!(
            current,
            entity(scope("00000000000000000000000000000002", HOST))
        );
        assert_ne!(
            current,
            entity(scope(TENANT, "00000000000000000000000000000101"))
        );
        assert_ne!(
            current,
            entity(EntityIdentityScope::SourceRecord {
                source: crate::EvidenceHash::from_bytes([1; 32]),
                record: 0
            })
        );
        assert_ne!(
            current,
            entity(EntityIdentityScope::ProcessLifetime {
                host: EventText::identifier(HOST).unwrap(),
                lifetime: EventText::identifier("42").unwrap()
            })
        );
        assert!(
            ObservedEntity::try_new(
                ObservedEntityKind::Process,
                "42",
                EntityIdentityScope::Host(EventText::identifier(HOST).unwrap())
            )
            .is_err()
        );
        assert!(
            ObservedEntity::try_new(
                ObservedEntityKind::Process,
                "42",
                EntityIdentityScope::Account(EventText::identifier(TENANT).unwrap())
            )
            .is_err()
        );
    }
    #[test]
    fn provider_process_scope_is_not_a_pid_scope_and_ids_are_bounded() {
        let entity =
            ObservedEntity::try_new(ObservedEntityKind::Process, "42", scope(TENANT, HOST))
                .unwrap();
        assert!(
            EntityObservation::try_new(
                entity.clone(),
                EntityRole::Subject,
                CommonField::ProcessEntityId
            )
            .is_ok()
        );
        assert!(
            EntityObservation::try_new(
                entity.clone(),
                EntityRole::Parent,
                CommonField::ProcessParentEntityId
            )
            .is_ok()
        );
        assert!(
            EntityObservation::try_new(entity, EntityRole::Subject, CommonField::ProcessPid)
                .is_err()
        );
        for id in [
            "0",
            "-1",
            "00042",
            "1.5",
            "1e3",
            "18446744073709551616",
            "42\n",
        ] {
            assert!(
                ObservedEntity::try_new(ObservedEntityKind::Process, id, scope(TENANT, HOST))
                    .is_err()
            );
        }
        assert!(
            ObservedEntity::try_new(
                ObservedEntityKind::Process,
                "18446744073709551615",
                scope(TENANT, HOST)
            )
            .is_ok()
        );
        assert!(
            ObservedEntity::try_new(ObservedEntityKind::Host, HOST, scope(TENANT, HOST)).is_err()
        );
        for invalid in [
            "",
            "../outside",
            "__overflow__",
            "0000000000000000000000000000000\n",
            "gggggggggggggggggggggggggggggggg",
        ] {
            assert!(
                EntityIdentityScope::provider_process(
                    ProcessIdentityProvider::CrowdStrikeFdr,
                    invalid,
                    HOST
                )
                .is_err()
            );
            assert!(
                EntityIdentityScope::provider_process(
                    ProcessIdentityProvider::CrowdStrikeFdr,
                    TENANT,
                    invalid
                )
                .is_err()
            );
        }
        assert!(ProcessIdentityProvider::parse("other-provider").is_err());
    }
}
