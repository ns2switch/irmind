//! Strict adapters for the domain's typed common projection.
mod codec;
mod values;
use crate::{AppError, FixedAppError, IndexedGraphRecord};
pub use codec::{decode_common_event, encode_common_event};
use irmind_domain::EvidenceHash;
pub use irmind_domain::{
    BoundedObservations, CategorySet, CommonEventFilter, CommonEventV1, CommonField,
    CommonFieldType, CommonValue, ContentHash, DnsAnswer, DnsAnswers, EntityIdentityScope,
    EntityObservation, EntityRole, EventCategory, EventContextV1, EventHeaderV1, EventKind,
    EventOrigin, EventOutcome, EventSchemaError, EventText, EventTextList, EventType, EventTypeSet,
    HashAlgorithm, NetworkDirection, ObservedEntity, ObservedEntityKind,
};

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

/// Checked, canonical projection of an immutably borrowed event. Validation
/// does not remove taint or authorize an action. Its constructor stays private.
pub struct CheckedCommonRecord<'a> {
    record: &'a CommonGraphRecord,
    encoded: String,
}
impl CheckedCommonRecord<'_> {
    pub const fn record(&self) -> &CommonGraphRecord {
        self.record
    }
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
    /// Move the already checked serialization; this does not remove source taint.
    pub fn into_encoded(self) -> String {
        self.encoded
    }
}

/// Validate the mapped projection against its authenticated decoder provenance.
pub fn validate_common_record(
    record: &CommonGraphRecord,
    provenance: &irmind_domain::Provenance,
    identity: crate::ParserIdentity<'_>,
) -> Result<(), AppError> {
    check_common_record(record, provenance, identity).map(|_| ())
}

/// A module cannot change which source/record its normalized event represents.
pub fn check_common_record<'a>(
    record: &'a CommonGraphRecord,
    provenance: &irmind_domain::Provenance,
    identity: crate::ParserIdentity<'_>,
) -> Result<CheckedCommonRecord<'a>, AppError> {
    let origin = record.common.origin();
    let hash = EvidenceHash::from_bytes(*provenance.evidence_hash());
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
    let encoded = encode_common_event(&record.common)?;
    Ok(CheckedCommonRecord { record, encoded })
}

#[cfg(test)]
mod tests;

pub fn encode_identity_scope(scope: &EntityIdentityScope) -> Result<String, AppError> {
    codec::encode_scope(scope)
}
pub fn decode_identity_scope(input: &str) -> Result<EntityIdentityScope, AppError> {
    codec::decode_scope(input)
}
