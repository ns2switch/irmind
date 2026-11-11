//! NDJSON framing depends on the authenticated logical name, never the spool name.
use super::{
    AppError, DecodeBudget, JsonFrames, ParseReport, PreparedFrame, SourceInput, SourceRecordV1,
    Tainted, decode_ordered, forward_prepared, invalid, prepare_frame, reject,
};
use std::io::{BufRead, BufReader};
const MAX_LINE: usize = 4 * 1024 * 1024;
const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;

pub(super) fn decode(
    input: SourceInput<'_>,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(input.reader);
    let metadata = input.metadata;
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    let mut offset = 0;
    decode_ordered(
        budget,
        metadata.cancel,
        || loop {
            let (bytes, consumed) = line(&mut reader, metadata.cancel, MAX_SOURCE - offset)?;
            if consumed == 0 {
                return Ok(None);
            }
            let start = offset;
            offset += consumed;
            if consumed <= MAX_LINE as u64 && bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let weight = bytes.len().saturating_mul(64);
            return Ok(Some(((bytes, start), weight)));
        },
        |(bytes, start)| {
            let result = prepare(&bytes, metadata.cancel);
            (bytes, start, result)
        },
        |(bytes, start, result)| {
            if report.accepted as u64 + report.rejected >= 10_000_000 {
                return Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit));
            }
            match result? {
                Some(frames) => {
                    for frame in frames {
                        forward_prepared(metadata, frame, start, &mut report, emit)?;
                    }
                }
                None => reject(&mut report, &bytes),
            }
            Ok(())
        },
    )?;
    Ok(report)
}

fn prepare(
    bytes: &[u8],
    cancel: &irmind_app::CancellationToken,
) -> Result<Option<Vec<PreparedFrame>>, AppError> {
    if bytes.len() > MAX_LINE || serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_err() {
        return Ok(None);
    }
    let mut cursor = bytes;
    let mut frames = JsonFrames::new(&mut cursor, cancel);
    let mut prepared = Vec::new();
    while let Some(frame) = frames.next_frame()? {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        prepared.push(prepare_frame(frame));
    }
    Ok(Some(prepared))
}

fn line(
    reader: &mut impl BufRead,
    cancel: &irmind_app::CancellationToken,
    remaining: u64,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut bytes = Vec::new();
    let mut consumed = 0u64;
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
            .map_or(available.len(), |p| p + 1);
        let newline = available[end - 1] == b'\n';
        let room = (MAX_LINE + 1).saturating_sub(bytes.len());
        bytes.extend_from_slice(&available[..end.min(room)]);
        consumed = consumed
            .checked_add(end as u64)
            .filter(|n| *n <= remaining)
            .ok_or(AppError::Fixed(irmind_app::FixedAppError::SourceLimit))?;
        reader.consume(end);
        if newline {
            return Ok((bytes, consumed));
        }
    }
}
