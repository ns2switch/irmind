//! Source-only RFC framing with confirmed per-ingestion calendar context.
mod fields;
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceDecoderSelection, SourceInput, SourceMetadata, SourceRecordV1,
        framed::SourceFrameEmitter,
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
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut reader = BufReader::new(input.reader);
        if reader
            .fill_buf()
            .map_err(|_| invalid())?
            .starts_with(&[0x1f, 0x8b])
        {
            compressed(&mut reader, input.metadata, emit)
        } else {
            lines(&mut reader, input.metadata, false, emit)
        }
    }
}
fn compressed(
    reader: &mut dyn Read,
    metadata: SourceMetadata<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let compressed = crate::gzip::bounded(reader, metadata.cancel);
    let gzip = flate2::read::MultiGzDecoder::new(compressed);
    let mut decoded = crate::gzip::bounded(gzip, metadata.cancel);
    let mut callback_failed = false;
    let result = lines(&mut decoded, metadata, true, &mut |record| {
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
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    let mut state = SourceFrameEmitter::new(metadata, SyslogSourceDecoder.identity());
    let mut calendar = metadata
        .time_context
        .copied()
        .map(irmind_app::ParserCalendar::new);
    let mut offset = 0u64;
    loop {
        let (bytes, size) = crate::input::frame(&mut reader, metadata.cancel)?;
        if size == 0 {
            return Ok(state.finish());
        }
        let start = offset;
        offset = offset.checked_add(size).ok_or_else(limit)?;
        if offset > 50 * 1024 * 1024 * 1024 {
            return Err(limit());
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let parsed = if size > 1024 * 1024 {
            Err(invalid())
        } else {
            std::str::from_utf8(&bytes)
                .map_err(|_| invalid())
                .and_then(|line| {
                    fields::decode(
                        line.trim_end_matches(['\r', '\n']),
                        metadata,
                        &mut calendar,
                        compressed,
                    )
                })
        }
        .map_err(|error| match error {
            error @ AppError::ParserTimeContextRequired { .. } => error,
            _ => invalid(),
        });
        state.frame(&bytes, (!compressed).then_some(start), parsed, emit)?;
    }
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
            .with_detector(|source, sample| crate::SyslogParser::default().detect(source, sample))
            .with_time_detector(|source, sample| {
                crate::SyslogParser::default().time_context_requirement(source, sample)
            }),
    )
}

#[cfg(test)]
mod tests;
