use super::{AppError, OffsetState, SourceRecordAccumulator, SourceRecordV1, invalid};
use irmind_domain::{Provenance, TimePrecision};

impl SourceRecordAccumulator<'_> {
    pub(super) fn validate(
        &self,
        source: &SourceRecordV1,
        provenance: &Provenance,
    ) -> Result<(), AppError> {
        let origin = source.origin();
        if self.records >= 10_000_000
            || self.previous.is_some_and(|n| origin.record() <= n)
            || origin.source() != &self.source_hash
            || origin.parser() != self.identity.id()
            || origin.parser_version() != self.identity.version()
            || source.reference() != self.metadata.source
            || provenance.evidence_hash() != &self.metadata.evidence_hash
            || provenance.record_index() != Some(origin.record())
            || provenance.source_kind() != self.metadata.source.kind()
            || source
                .timestamp()
                .is_some_and(|t| t.precision() == TimePrecision::Unknown)
        {
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
        match (origin.offset(), provenance.parser_location()) {
            (Some(offset), Some(location))
                if offset < self.source_size
                    && location.byte_offset() == offset
                    && location.source() == source.source()
                    && location.parser_id() == self.identity.id() => {}
            (None, None) => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
}
