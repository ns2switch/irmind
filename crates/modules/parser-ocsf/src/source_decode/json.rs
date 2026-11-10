use super::{
    AppError, ParseReport, Read, SourceInput, SourceRecordV1, State, Tainted, invalid, limit,
};
use irmind_app::source_mapping::json::{JsonFrames, SourceJsonLimits, decode_json_fields};
use std::io::{BufRead, BufReader};
pub(super) fn decode(
    input: &mut SourceInput<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    if input.metadata.cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let mut callback_failed = false;
    let mut forward = |record| {
        let result = emit(record);
        callback_failed |= result.is_err();
        result
    };
    let mut limited = input.reader.take(crate::json_stream::MAX_SOURCE_BYTES + 1);
    let result = {
        let mut reader = BufReader::new(&mut limited);
        let prefix = reader.fill_buf().map_err(|_| invalid())?.trim_ascii_start();
        let line = prefix
            .split(|b| *b == b'\n')
            .next()
            .unwrap_or_default()
            .trim_ascii();
        let known_lines = std::path::Path::new(input.metadata.source.reference())
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("ndjson") || e.eq_ignore_ascii_case("jsonl"));
        let document = line == b"{"
            || line == b"["
            || (prefix.first() == Some(&b'[') && (!known_lines || !prefix.contains(&b'\n')))
            || (!known_lines && decode_json_fields(line, SourceJsonLimits::default()).is_err());
        let mut state = State::new(input.metadata, "ocsf-json");
        if document {
            frames(&mut reader, &mut state, &mut forward)
        } else {
            lines(&mut reader, &mut state, &mut forward)
        }
        .map(|()| state.report)
    };
    if !callback_failed && limited.limit() == 0 {
        Err(limit())
    } else {
        result
    }
}
fn frames(
    reader: &mut dyn Read,
    state: &mut State<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let mut frames = JsonFrames::new(reader, state.metadata.cancel).without_record_wrappers();
    while let Some(frame) = frames.next_frame()? {
        if frame.oversized() {
            if state.seen >= 10_000_000 {
                return Err(limit());
            }
            state.seen += 1;
            state.reject(frame.bytes());
        } else {
            state.record(frame.bytes(), Some(frame.offset()), emit)?;
        }
    }
    Ok(())
}
fn lines(
    reader: &mut impl BufRead,
    state: &mut State<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let mut offset = 0u64;
    loop {
        let (bytes, consumed) = crate::json_stream::bounded_line(
            reader,
            state.metadata.cancel,
            crate::json_stream::MAX_SOURCE_BYTES.saturating_sub(offset),
        )?;
        if consumed == 0 {
            return Ok(());
        }
        let start = offset;
        offset = offset.checked_add(consumed).ok_or_else(limit)?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        state.record(&bytes, Some(start), emit)?;
    }
}
