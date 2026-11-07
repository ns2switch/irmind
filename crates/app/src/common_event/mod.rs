//! Strict adapters for the domain's typed common projection.
mod codec;
mod values;
use crate::{AppError, FixedAppError, IndexedGraphRecord};
pub use codec::{decode_common_event, encode_common_event};
pub use irmind_domain::{
    BoundedObservations, CategorySet, CommonEventFilter, CommonEventV1, CommonField,
    CommonFieldType, CommonValue, ContentHash, DnsAnswer, DnsAnswers, EntityIdentityScope,
    EntityObservation, EntityRole, EventCategory, EventContextV1, EventHeaderV1, EventKind,
    EventOrigin, EventOutcome, EventSchemaError, EventText, EventTextList, EventType, EventTypeSet,
    HashAlgorithm, NetworkDirection, ObservedEntity, ObservedEntityKind,
};
use irmind_domain::{EvidenceHash, Tainted};

#[derive(Clone, Eq, PartialEq)]
pub struct CommonGraphRecord {
    pub indexed: IndexedGraphRecord,
    pub common: CommonEventV1,
}

impl std::fmt::Debug for CommonGraphRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonGraphRecord")
            .field("origin", self.common.origin())
            .finish_non_exhaustive()
    }
}

pub(crate) fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::PolicyInvalidCommonEvent)
}

/// The compatibility bridge does not inspect JSON or guess classifications/roles.
pub fn lift_unclassified_common(
    record: &Tainted<IndexedGraphRecord>,
    parser: crate::ParserIdentity<'_>,
) -> Result<Tainted<CommonGraphRecord>, AppError> {
    let hash = EvidenceHash::parse(&crate::hex(record.provenance().evidence_hash()))
        .map_err(|_| invalid())?;
    let mut output = None;
    record.inspect(|indexed| {
        output = Some((|| {
            let origin = EventOrigin::try_new(
                hash,
                u64::try_from(indexed.record.index).map_err(|_| invalid())?,
                indexed.source_offset,
                parser.name,
                parser.version,
            )
            .map_err(|_| invalid())?;
            let common = CommonEventV1::try_new(
                origin,
                indexed.time,
                EventHeaderV1::default(),
                EventContextV1::default(),
                BoundedObservations::default(),
            )
            .map_err(|_| invalid())?;
            Ok(Tainted::from_external(
                CommonGraphRecord {
                    indexed: indexed.clone(),
                    common,
                },
                record.provenance().clone(),
            ))
        })());
    });
    output.ok_or_else(invalid)?
}

/// A module cannot change which source/record its normalized event represents.
pub fn validate_common_record(
    record: &CommonGraphRecord,
    provenance: &irmind_domain::Provenance,
    identity: crate::ParserIdentity<'_>,
) -> Result<(), AppError> {
    let origin = record.common.origin();
    let hash =
        EvidenceHash::parse(&crate::hex(provenance.evidence_hash())).map_err(|_| invalid())?;
    let index = u64::try_from(record.indexed.record.index).map_err(|_| invalid())?;
    if origin.source() != &hash
        || origin.record() != index
        || origin.offset() != record.indexed.source_offset
        || origin.parser() != identity.name
        || origin.parser_version() != identity.version
        || record.common.timestamp() != record.indexed.time
        || provenance
            .record_index()
            .is_some_and(|value| value != index)
    {
        return Err(invalid());
    }
    encode_common_event(&record.common)?;
    Ok(())
}

#[cfg(test)]
mod tests;

pub fn encode_identity_scope(scope: &EntityIdentityScope) -> Result<String, AppError> {
    codec::encode_scope(scope)
}
pub fn decode_identity_scope(input: &str) -> Result<EntityIdentityScope, AppError> {
    codec::decode_scope(input)
}
