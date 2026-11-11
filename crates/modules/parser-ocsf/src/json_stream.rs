use crate::policy_error;
use irmind_app::{AppError, CancellationToken};
use std::io::BufRead;

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;

pub(super) fn bounded_line(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
    remaining: u64,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut line = Vec::new();
    let mut consumed = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let available = reader
            .fill_buf()
            .map_err(|_| policy_error("cannot read OCSF source"))?;
        if available.is_empty() {
            return Ok((line, consumed));
        }
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        let newline = available[end - 1] == b'\n';
        let room = MAX_RECORD_BYTES
            .saturating_add(1)
            .saturating_sub(line.len());
        line.extend_from_slice(&available[..end.min(room)]);
        consumed = consumed.saturating_add(end as u64);
        if consumed > remaining {
            return Err(policy_error("OCSF source exceeds 50 GiB"));
        }
        reader.consume(end);
        if newline {
            return Ok((line, consumed));
        }
    }
}
