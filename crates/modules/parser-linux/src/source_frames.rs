//! Faithful Linux framing; no category, outcome or entity role is chosen here.
mod audit;
mod auth;
mod record;
mod web;
use super::{bounds, time::Calendar};
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceInput, SourceMetadata, SourceRecordV1,
        ordered_decode::decode_ordered,
    },
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
        self.decode_with_budget(DecodeInput::Reader(input), DecodeBudget::sequential(), emit)
    }
    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let SourceInput { metadata, reader } = input.into_reader();
        let mut reader = BufReader::new(reader);
        let mut state = State::new(metadata, emit);
        let (mut index, mut offset) = (0u64, 0u64);
        decode_ordered(
            budget,
            metadata.cancel,
            || loop {
                let (bytes, consumed) = bounds::line(&mut reader, metadata.cancel)?;
                if consumed == 0 {
                    return Ok(None);
                }
                if index >= bounds::MAX_RECORDS as u64 || offset + consumed > bounds::MAX_SOURCE {
                    return Err(invalid());
                }
                let item = (bytes, index, offset, consumed > bounds::MAX_LINE as u64);
                index += 1;
                offset += consumed;
                if item.3 || !item.0.iter().all(u8::is_ascii_whitespace) {
                    let weight = item.0.len().saturating_mul(64);
                    return Ok(Some((item, weight)));
                }
            },
            |(bytes, index, offset, oversized)| {
                let prepared = if oversized {
                    Prepared::Invalid
                } else {
                    prepare(&bytes, index, offset)
                };
                (bytes, index, offset, prepared)
            },
            |(bytes, index, offset, prepared)| state.accept(&bytes, index, offset, prepared),
        )?;
        for decoded in state.audit.finish()? {
            state.emit(decoded)?;
        }
        Ok(state.report)
    }
}
enum Prepared {
    Invalid,
    Audit,
    Authentication,
    Independent(Box<Result<Decoded, AppError>>),
}

fn text(bytes: &[u8]) -> Result<&str, AppError> {
    std::str::from_utf8(bytes)
        .map(|line| line.trim_end_matches(['\r', '\n']))
        .map_err(|_| invalid())
}

fn prepare(bytes: &[u8], index: u64, offset: u64) -> Prepared {
    let Ok(line) = std::str::from_utf8(bytes) else {
        return Prepared::Invalid;
    };
    let line = line.trim_end_matches(['\r', '\n']);
    if super::audit::detect(line) {
        Prepared::Audit
    } else if line.starts_with('{') {
        Prepared::Independent(Box::new(record::journal(line, index, offset)))
    } else if super::auth::header(line).is_some() {
        Prepared::Authentication
    } else {
        Prepared::Independent(Box::new(web::decode(line, index, offset)))
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
    fn accept(
        &mut self,
        bytes: &[u8],
        index: u64,
        offset: u64,
        prepared: Prepared,
    ) -> Result<(), AppError> {
        if matches!(prepared, Prepared::Invalid) {
            self.reject(bytes);
            return Ok(());
        }
        let is_audit = matches!(prepared, Prepared::Audit);
        if *self.audit_mode.get_or_insert(is_audit) != is_audit {
            self.reject(bytes);
            return Ok(());
        }
        let result = match prepared {
            Prepared::Audit => self.audit.push(text(bytes)?, index, offset),
            Prepared::Authentication => {
                auth::decode(self.meta, text(bytes)?, index, offset, &mut self.calendar)
                    .map(|record| vec![record])
            }
            Prepared::Independent(result) => result.map(|record| vec![record]),
            Prepared::Invalid => return Err(invalid()),
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
        irmind_app::LogParser::detect(&super::LinuxParser, source, sample)
    }
    fn time(
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        super::time::requirement(&super::LinuxParser, source, sample)
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
