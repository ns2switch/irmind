use super::{
    AppError, EvidenceHash, OffsetState, SourceDecoderIdentityV1, SourceMetadata,
    SourceRecordAccumulator, SourceRecordV1, invalid,
};
use irmind_domain::{Provenance, TimePrecision};

impl SourceRecordAccumulator<'_> {
    pub(super) fn validate(
        &self,
        source: &SourceRecordV1,
        provenance: &Provenance,
    ) -> Result<(), AppError> {
        validate_binding(
            &Binding {
                metadata: self.metadata,
                identity: &self.identity,
                hash: &self.source_hash,
                size: self.source_size,
            },
            source,
            provenance,
        )?;
        let origin = source.origin();
        if self.records >= 10_000_000 || self.previous.is_some_and(|n| origin.record() <= n) {
            return Err(invalid());
        }
        match (self.offset, origin.offset()) {
            (OffsetState::Known(previous), Some(current)) if current < previous => {
                return Err(invalid());
            }
            (OffsetState::Known(_), None) | (OffsetState::Unavailable, Some(_)) => {
                return Err(invalid());
            }
            _ => {}
        }
        Ok(())
    }
}

pub(super) struct Binding<'a> {
    pub(super) metadata: SourceMetadata<'a>,
    pub(super) identity: &'a SourceDecoderIdentityV1,
    pub(super) hash: &'a EvidenceHash,
    pub(super) size: u64,
}

pub(super) fn validate_binding(
    binding: &Binding<'_>,
    source: &SourceRecordV1,
    provenance: &Provenance,
) -> Result<(), AppError> {
    let origin = source.origin();
    if origin.source() != binding.hash
        || origin.parser() != binding.identity.id()
        || origin.parser_version() != binding.identity.version()
        || source.reference() != binding.metadata.source
        || provenance.evidence_hash() != &binding.metadata.evidence_hash
        || provenance.record_index() != Some(origin.record())
        || provenance.source_kind() != binding.metadata.source.kind()
        || source
            .timestamp()
            .is_some_and(|t| t.precision() == TimePrecision::Unknown)
    {
        return Err(invalid());
    }
    match (origin.offset(), provenance.parser_location()) {
        (Some(offset), Some(location))
            if offset < binding.size
                && location.byte_offset() == offset
                && location.source() == source.source()
                && location.parser_id() == binding.identity.id() => {}
        (None, None) => {}
        _ => return Err(invalid()),
    }
    Ok(())
}
