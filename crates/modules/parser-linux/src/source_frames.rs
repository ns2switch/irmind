//! Faithful Linux framing; no category, outcome or entity role is chosen here.
mod audit;
mod auth;
mod record;
mod web;
use super::{bounds, time::Calendar};
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1},
};
use irmind_domain::{ParserLocation, Provenance, Tainted};
use record::Decoded;
use std::{io::BufReader, sync::Arc};
pub struct LinuxSourceDecoder;
pub(super) const VERSION: &str = "linux-source-v1";

impl SourceDecoder for LinuxSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-linux",
            version: VERSION,
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let mut reader = BufReader::new(input.reader);
        let mut state = State::new(input.metadata, emit);
        let (mut index, mut offset) = (0u64, 0u64);
        loop {
            let (bytes, consumed) = bounds::line(&mut reader, input.metadata.cancel)?;
            if consumed == 0 {
                break;
            }
            if index >= bounds::MAX_RECORDS as u64 || offset + consumed > bounds::MAX_SOURCE {
                return Err(invalid());
            }
            if consumed > bounds::MAX_LINE as u64 {
                state.reject(&bytes);
            } else if !bytes.iter().all(u8::is_ascii_whitespace) {
                state.line(&bytes, index, offset)?;
            }
            index += 1;
            offset += consumed;
        }
        for decoded in state.audit.finish()? {
            state.emit(decoded)?;
        }
        Ok(state.report)
    }
}
struct State<'a> {
    meta: SourceMetadata<'a>,
    emit: &'a mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    calendar: Option<Calendar>,
    audit: audit::Groups,
    audit_mode: Option<bool>,
    report: ParseReport,
}
impl<'a> State<'a> {
    fn new(
        meta: SourceMetadata<'a>,
        emit: &'a mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Self {
        Self {
            meta,
            emit,
            calendar: meta.time_context.copied().map(Calendar::new),
            audit: audit::Groups::default(),
            audit_mode: None,
            report: ParseReport {
                accepted: 0,
                rejected: 0,
                samples: vec![],
            },
        }
    }
    fn reject(&mut self, bytes: &[u8]) {
        self.audit.invalidate_open();
        bounds::reject(&mut self.report, bytes);
    }
    fn line(&mut self, bytes: &[u8], index: u64, offset: u64) -> Result<(), AppError> {
        let Ok(line) = std::str::from_utf8(bytes) else {
            self.reject(bytes);
            return Ok(());
        };
        let line = line.trim_end_matches(['\r', '\n']);
        let is_audit = super::audit::detect(line);
        if *self.audit_mode.get_or_insert(is_audit) != is_audit {
            self.reject(bytes);
            return Ok(());
        }
        let result = if is_audit {
            self.audit.push(line, index, offset)
        } else {
            self.single(line, index, offset).map(|r| vec![r])
        };
        match result {
            Ok(records) => {
                for record in records {
                    self.emit(record)?;
                }
            }
            Err(e @ AppError::ParserTimeContextRequired { .. }) => return Err(e),
            Err(AppError::Cancelled) => return Err(AppError::Cancelled),
            Err(_) => self.reject(bytes),
        }
        Ok(())
    }
    fn single(&mut self, line: &str, index: u64, offset: u64) -> Result<Decoded, AppError> {
        if line.starts_with('{') {
            record::journal(line, index, offset)
        } else if super::auth::header(line).is_some() {
            auth::decode(self.meta, line, index, offset, &mut self.calendar)
        } else {
            web::decode(line, index, offset)
        }
    }
    fn emit(&mut self, decoded: Decoded) -> Result<(), AppError> {
        if self.meta.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let Ok(source) = decoded.into_source(self.meta, self.report.accepted as u64) else {
            bounds::reject(&mut self.report, b"invalid grouped source representation");
            return Ok(());
        };
        let mut provenance = Provenance::new(
            self.meta.evidence_hash,
            Some(source.origin().record()),
            self.meta.source.kind(),
        );
        if let Some(offset) = source.origin().offset() {
            provenance = provenance.with_parser_location(
                ParserLocation::new(self.meta.source.reference(), "parser-linux", offset)
                    .map_err(|_| invalid())?,
            );
        }
        (self.emit)(Tainted::from_external(source, provenance))?;
        self.report.accepted += 1;
        Ok(())
    }
}
pub fn source_log_parser() -> Arc<dyn irmind_app::LogParser> {
    fn detect(source: &str, sample: &[u8]) -> Option<irmind_app::ParserConfidence> {
        irmind_app::LogParser::detect(&super::LinuxParser::default(), source, sample)
    }
    fn time(
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        super::time::requirement(&super::LinuxParser::default(), source, sample)
    }
    Arc::new(
        irmind_app::source_mapping::SourceDecoderSelection::new(Arc::new(LinuxSourceDecoder))
            .with_detector(detect)
            .with_time_detector(time),
    )
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
