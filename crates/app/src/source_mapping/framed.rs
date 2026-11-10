//! Shared bounded framing mechanics. Source modules still own their format and time rules.
mod json;
mod time;
use super::{DecodeAnnotationsV1, SourceFormatV1, SourceMetadata, SourceRecordV1, SourceValue};
use crate::{AppError, FixedAppError, ParseReport, ParserIdentity};
use irmind_domain::{
    EventOrigin, EvidenceHash, IndexedTime, ParserLocation, Provenance, SourceMemberV1, Tainted,
};
pub use json::decode_json_source;
pub use time::source_datetime;

pub struct DecodedSourceFrame {
    pub fields: SourceValue,
    pub timestamp: Option<IndexedTime>,
    pub format: SourceFormatV1,
}
/// Accepts original decoded fields only, never a normalized `GraphRecord` projection.
pub struct SourceFrameEmitter<'a> {
    metadata: SourceMetadata<'a>,
    parser: String,
    version: String,
    source_hash: EvidenceHash,
    seen: u64,
    report: ParseReport,
}
impl<'a> SourceFrameEmitter<'a> {
    #[must_use]
    pub fn new(metadata: SourceMetadata<'a>, identity: ParserIdentity<'_>) -> Self {
        Self {
            metadata,
            parser: identity.name.to_owned(),
            version: identity.version.to_owned(),
            source_hash: EvidenceHash::from_bytes(metadata.evidence_hash),
            seen: 0,
            report: ParseReport {
                accepted: 0,
                rejected: 0,
                samples: Vec::new(),
            },
        }
    }
    pub fn frame(
        &mut self,
        bytes: &[u8],
        offset: Option<u64>,
        decoded: Result<DecodedSourceFrame, AppError>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        if self.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if self.seen >= 10_000_000 {
            return Err(limit());
        }
        let ordinal = self.seen;
        self.seen += 1;
        let record = decoded.and_then(|frame| self.record(frame, offset, ordinal));
        match record {
            Ok(record) => {
                emit(record)?;
                self.report.accepted += 1;
            }
            Err(AppError::Fixed(FixedAppError::SourceFormat | FixedAppError::SourceLimit)) => {
                self.reject(bytes);
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
    fn record(
        &self,
        frame: DecodedSourceFrame,
        offset: Option<u64>,
        ordinal: u64,
    ) -> Result<Tainted<SourceRecordV1>, AppError> {
        let record = self.report.accepted as u64;
        let origin = EventOrigin::try_new(
            self.source_hash.clone(),
            record,
            offset,
            &self.parser,
            &self.version,
        )
        .map_err(|_| invalid())?;
        let decoded = SourceRecordV1::try_from_source(
            origin,
            self.metadata.source.clone(),
            frame.timestamp,
            frame.format,
            frame.fields,
            DecodeAnnotationsV1::try_new(false, vec![SourceMemberV1 { ordinal, offset }], None)
                .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let mut provenance = Provenance::new(
            self.metadata.evidence_hash,
            Some(record),
            self.metadata.source.kind(),
        );
        if let Some(offset) = offset {
            provenance = provenance.with_parser_location(
                ParserLocation::new(self.metadata.source.reference(), &self.parser, offset)
                    .map_err(|_| invalid())?,
            );
        }
        Ok(Tainted::from_external(decoded, provenance))
    }
    fn reject(&mut self, bytes: &[u8]) {
        self.report.rejected += 1;
        if self.report.samples.len() < 3 {
            self.report.samples.push(
                String::from_utf8_lossy(&bytes[..bytes.len().min(256)])
                    .chars()
                    .flat_map(char::escape_default)
                    .take(256)
                    .collect(),
            );
        }
    }
    #[must_use]
    pub fn finish(self) -> ParseReport {
        self.report
    }
}
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn limit() -> AppError {
    AppError::Fixed(FixedAppError::SourceLimit)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
