use super::{DecodedSourceFrame, SourceFrameEmitter, invalid, limit};
use crate::{
    AppError, ParseReport, ParserIdentity,
    source_mapping::{
        SourceInput, SourceRecordV1, SourceValue,
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::Tainted;
use std::io::{BufRead, BufReader, Read};
const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;
/// Decode each bounded original JSON object before a source module extracts its timestamp.
pub fn decode_json_source(
    input: SourceInput<'_>,
    identity: ParserIdentity<'_>,
    decode: &mut dyn FnMut(SourceValue) -> Result<DecodedSourceFrame, AppError>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    if input.metadata.cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let mut state = SourceFrameEmitter::new(input.metadata, identity);
    let mut reader = BufReader::new(input.reader);
    let prefix = reader.fill_buf().map_err(|_| invalid())?.trim_ascii_start();
    let line = prefix
        .split(|b| *b == b'\n')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    // A malformed complete JSONL row stays a rejected row, not a whole document.
    let known_lines = std::path::Path::new(input.metadata.source.reference())
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ndjson") || e.eq_ignore_ascii_case("jsonl"));
    let incomplete_object = prefix.first() == Some(&b'{')
        && serde_json::from_slice::<serde::de::IgnoredAny>(line).is_err_and(|e| e.is_eof());
    let document =
        prefix.first() == Some(&b'[') || line == b"{" || (!known_lines && incomplete_object);
    if document {
        let mut limited = reader.take(MAX_SOURCE + 1);
        {
            let mut frames =
                JsonFrames::new(&mut limited, input.metadata.cancel).without_record_wrappers();
            while let Some(frame) = frames.next_frame()? {
                let decoded = if frame.oversized() {
                    Err(invalid())
                } else {
                    decode_json_fields(frame.bytes(), SourceJsonLimits::default())
                        .map_err(|_| invalid())
                        .and_then(&mut *decode)
                };
                state.frame(frame.bytes(), Some(frame.offset()), decoded, emit)?;
            }
        }
        if limited.limit() == 0 {
            return Err(limit());
        }
    } else {
        let mut offset = 0;
        loop {
            let (bytes, size) =
                line_frame(&mut reader, input.metadata.cancel, MAX_SOURCE - offset)?;
            if size == 0 {
                break;
            }
            let start = offset;
            offset += size;
            if bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let decoded = decode_json_fields(&bytes, SourceJsonLimits::default())
                .map_err(|_| invalid())
                .and_then(&mut *decode);
            state.frame(&bytes, Some(start), decoded, emit)?;
        }
    }
    Ok(state.finish())
}
fn line_frame(
    reader: &mut impl BufRead,
    cancel: &crate::CancellationToken,
    remaining: u64,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut bytes = Vec::new();
    let mut consumed = 0;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let available = reader.fill_buf().map_err(|_| invalid())?;
        if available.is_empty() {
            return Ok((bytes, consumed));
        }
        let end = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        let newline = available[end - 1] == b'\n';
        bytes.extend_from_slice(
            &available
                [..end.min((irmind_domain::SOURCE_MAX_BYTES + 1).saturating_sub(bytes.len()))],
        );
        consumed += end as u64;
        if consumed > remaining {
            return Err(limit());
        }
        reader.consume(end);
        if newline {
            return Ok((bytes, consumed));
        }
    }
}
