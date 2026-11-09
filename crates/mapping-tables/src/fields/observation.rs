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
}
enum CompiledScope {
    Global,
    SourceRecord,
    Host(SourcePath),
    Account(SourcePath),
}
impl CompiledObservation {
    pub(super) fn compile(value: Observation, target: CommonField) -> Result<Self, MappingError> {
        let result = Self {
            kind: ObservedEntityKind::parse(&value.kind).map_err(invalid)?,
            role: EntityRole::parse(&value.role).map_err(invalid)?,
            scope: match value.scope {
                Scope::Global => CompiledScope::Global,
                Scope::SourceRecord => CompiledScope::SourceRecord,
                Scope::Host(keys) => CompiledScope::Host(path(&keys)?),
                Scope::Account(keys) => CompiledScope::Account(path(&keys)?),
            },
        };
        let dummy = match result.kind {
            ObservedEntityKind::Ip => "203.0.113.1",
            ObservedEntityKind::Domain => "example.test",
            ObservedEntityKind::Hash => "00000000000000000000000000000000",
            _ => "synthetic",
        };
        let scope = match result.scope {
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
            CompiledScope::Global => EntityIdentityScope::Global,
            CompiledScope::SourceRecord => EntityIdentityScope::SourceRecord {
                source: source.origin().source().clone(),
                record: source.origin().record(),
            },
            CompiledScope::Host(p) => EntityIdentityScope::Host(named(p)?),
            CompiledScope::Account(p) => EntityIdentityScope::Account(named(p)?),
        };
        EntityObservation::try_new(
            ObservedEntity::try_new(self.kind, &text, scope).map_err(|_| bad())?,
            self.role,
            field,
        )
        .map_err(|_| bad())
    }
}
