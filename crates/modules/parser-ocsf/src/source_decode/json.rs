use super::{
    AppError, ParseReport, Read, SourceInput, SourceRecordV1, State, Tainted, invalid, limit,
};
use irmind_app::source_mapping::{
    DecodeBudget,
    json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    ordered_decode::decode_ordered,
};
use std::io::{BufRead, BufReader};
pub(super) fn decode(
    input: &mut SourceInput<'_>,
    budget: DecodeBudget,
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
            frames(&mut reader, &mut state, budget, &mut forward)
        } else {
            lines(&mut reader, &mut state, budget, &mut forward)
        }
        .map(|()| state.report)
    };
    if !callback_failed && limited.limit() == 0 {
        Err(limit())
    } else {
        result
    }
}
type Frame = (Vec<u8>, u64, bool);

fn frames(
    reader: &mut dyn Read,
    state: &mut State<'_>,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let mut frames = JsonFrames::new(reader, state.metadata.cancel).without_record_wrappers();
    records(
        state,
        budget,
        || {
            Ok(frames.next_frame()?.map(|frame| {
                let (offset, oversized) = (frame.offset(), frame.oversized());
                (frame.into_bytes(), offset, oversized)
            }))
        },
        emit,
    )
}
fn lines(
    reader: &mut impl BufRead,
    state: &mut State<'_>,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let mut offset = 0u64;
    let cancel = state.metadata.cancel;
    records(
        state,
        budget,
        || loop {
            let (bytes, consumed) = crate::json_stream::bounded_line(
                reader,
                cancel,
                crate::json_stream::MAX_SOURCE_BYTES.saturating_sub(offset),
            )?;
            if consumed == 0 {
                return Ok(None);
            }
            let start = offset;
            offset = offset.checked_add(consumed).ok_or_else(limit)?;
            if !bytes.iter().all(u8::is_ascii_whitespace) {
                return Ok(Some((bytes, start, false)));
            }
        },
        emit,
    )
}

fn records(
    state: &mut State<'_>,
    budget: DecodeBudget,
    mut next: impl FnMut() -> Result<Option<Frame>, AppError>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let mut seen = state.seen;
    decode_ordered(
        budget,
        state.metadata.cancel,
        || {
            let Some(frame) = next()? else {
                return Ok(None);
            };
            if seen >= 10_000_000 {
                return Err(limit());
            }
            seen += 1;
            let weight = frame.0.len().saturating_mul(64);
            Ok(Some((frame, weight)))
        },
        |(bytes, offset, oversized)| {
            let parsed = if oversized {
                Err(invalid())
            } else {
                decode_json_fields(&bytes, SourceJsonLimits::default()).map_err(|_| invalid())
            };
            (bytes, offset, parsed)
        },
        |(bytes, offset, parsed)| state.record(&bytes, parsed, Some(offset), emit),
    )
}
