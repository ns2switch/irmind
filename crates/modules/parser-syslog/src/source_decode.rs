//! Source-only RFC framing with confirmed per-ingestion calendar context.
mod fields;
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceDecoderSelection, SourceInput, SourceMetadata,
        SourceRecordV1, framed::SourceFrameEmitter, ordered_decode::decode_ordered,
    },
};
use irmind_domain::Tainted;
use std::{
    io::{BufRead, BufReader, Read},
    sync::Arc,
};
pub struct SyslogSourceDecoder;
const VERSION: &str = "syslog-source-v1";
impl SourceDecoder for SyslogSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-syslog",
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
        let input = input.into_reader();
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut reader = BufReader::new(input.reader);
        if reader
            .fill_buf()
            .map_err(|_| invalid())?
            .starts_with(&[0x1f, 0x8b])
        {
            compressed(&mut reader, input.metadata, budget, emit)
        } else {
            lines(&mut reader, input.metadata, false, budget, emit)
        }
    }
}
fn compressed(
    reader: &mut dyn Read,
    metadata: SourceMetadata<'_>,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let compressed = crate::gzip::bounded(reader, metadata.cancel);
    let gzip = flate2::read::MultiGzDecoder::new(compressed);
    let mut decoded = crate::gzip::bounded(gzip, metadata.cancel);
    let mut callback_failed = false;
    let result = lines(&mut decoded, metadata, true, budget, &mut |record| {
        let result = emit(record);
        callback_failed |= result.is_err();
        result
    });
    if callback_failed {
        return result;
    }
    if metadata.cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    if decoded.exceeded() || decoded.inner().get_ref().exceeded() {
        return Err(limit());
    }
    result.map_err(|error| match error {
        AppError::Storage(_) => invalid(),
        other => other,
    })
}
fn lines(
    reader: &mut dyn Read,
    metadata: SourceMetadata<'_>,
    compressed: bool,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    let mut state = SourceFrameEmitter::new(metadata, SyslogSourceDecoder.identity());
    let mut calendar = metadata
        .time_context
        .copied()
        .map(irmind_app::ParserCalendar::new);
    let mut offset = 0u64;
    let mut seen = 0u64;
    decode_ordered(
        budget,
        metadata.cancel,
        || loop {
            let (bytes, size) = crate::input::frame(&mut reader, metadata.cancel)?;
            if size == 0 {
                return Ok(None);
            }
            let start = offset;
            offset = offset.checked_add(size).ok_or_else(limit)?;
            if offset > 50 * 1024 * 1024 * 1024 {
                return Err(limit());
            }
            if size <= 1024 * 1024 && bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if seen >= 10_000_000 {
                return Err(limit());
            }
            seen += 1;
            let weight = bytes.len().saturating_mul(64);
            return Ok(Some(((bytes, start, size > 1024 * 1024), weight)));
        },
        |(bytes, start, oversized)| {
            let decoded = if oversized {
                Some(Err(invalid()))
            } else {
                prepare_modern(&bytes, metadata, compressed)
            };
            (bytes, start, decoded)
        },
        |(bytes, start, decoded)| {
            // Classic records resolve year rollover in canonical order.
            let decoded =
                decoded.unwrap_or_else(|| parse_line(&bytes, metadata, &mut calendar, compressed));
            state.frame(&bytes, (!compressed).then_some(start), decoded, emit)
        },
    )?;
    Ok(state.finish())
}

fn prepare_modern(
    bytes: &[u8],
    metadata: SourceMetadata<'_>,
    compressed: bool,
) -> Option<Result<irmind_app::source_mapping::framed::DecodedSourceFrame, AppError>> {
    let line = match line_text(bytes) {
        Ok(line) => line,
        Err(error) => return Some(Err(error)),
    };
    match crate::record::priority(line) {
        Ok((_, rest)) if rest.starts_with("1 ") => {
            Some(parse_line(bytes, metadata, &mut None, compressed))
        }
        Ok(_) => None,
        Err(_) => Some(Err(invalid())),
    }
}

fn line_text(bytes: &[u8]) -> Result<&str, AppError> {
    std::str::from_utf8(bytes)
        .map(|line| line.trim_end_matches(['\r', '\n']))
        .map_err(|_| invalid())
}

fn parse_line(
    bytes: &[u8],
    metadata: SourceMetadata<'_>,
    calendar: &mut Option<irmind_app::ParserCalendar>,
    compressed: bool,
) -> Result<irmind_app::source_mapping::framed::DecodedSourceFrame, AppError> {
    fields::decode(line_text(bytes)?, metadata, calendar, compressed).map_err(|error| match error {
        error @ AppError::ParserTimeContextRequired { .. } => error,
        _ => invalid(),
    })
}

fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
fn limit() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceLimit)
}
pub fn source_log_parser() -> Arc<dyn LogParser> {
    Arc::new(
        SourceDecoderSelection::new(Arc::new(SyslogSourceDecoder))
            .with_detector(|source, sample| crate::SyslogParser.detect(source, sample))
            .with_time_detector(|source, sample| {
                crate::SyslogParser.time_context_requirement(source, sample)
            }),
    )
}

#[cfg(test)]
mod tests;
