use super::{AppError, CancellationToken};
use std::io::BufRead;

const MAX_LINE: usize = 1024 * 1024;
const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;

pub(super) fn frame(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut bytes = Vec::new();
    let mut consumed = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let chunk = reader
            .fill_buf()
            .map_err(|_| AppError::Storage("cannot read syslog source".into()))?;
        if chunk.is_empty() {
            return Ok((bytes, consumed));
        }
        let count = chunk
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(chunk.len(), |index| index + 1);
        let done = chunk[count - 1] == b'\n';
        let keep = count.min(MAX_LINE.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk[..keep]);
        reader.consume(count);
        consumed += count as u64;
        if consumed > MAX_SOURCE {
            return Err(super::limit());
        }
        if done {
            return Ok((bytes, consumed));
        }
    }
}
