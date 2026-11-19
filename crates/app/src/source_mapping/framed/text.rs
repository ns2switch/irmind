//! Bounded physical lines for text exports; embedded data never selects framing.
use crate::{AppError, CancellationToken, FixedAppError};
use std::io::BufRead;
pub fn text_frame(
    reader: &mut dyn BufRead,
    cancel: &CancellationToken,
    remaining: u64,
) -> Result<Option<(Vec<u8>, u64)>, AppError> {
    let mut bytes = Vec::new();
    let mut consumed = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let chunk = reader
            .fill_buf()
            .map_err(|_| AppError::Fixed(FixedAppError::SourceFormat))?;
        if chunk.is_empty() {
            return Ok((consumed != 0).then_some((bytes, consumed)));
        }
        let end = chunk
            .iter()
            .position(|b| *b == b'\n')
            .map_or(chunk.len(), |i| i + 1);
        consumed = consumed
            .checked_add(end as u64)
            .ok_or(AppError::Fixed(FixedAppError::SourceLimit))?;
        if consumed > remaining {
            return Err(AppError::Fixed(FixedAppError::SourceLimit));
        }
        let keep = end.min((irmind_domain::SOURCE_MAX_BYTES + 1).saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk[..keep]);
        let done = chunk[end - 1] == b'\n';
        reader.consume(end);
        if done {
            return Ok(Some((bytes, consumed)));
        }
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn oversized_and_hostile_quotes_do_not_consume_the_next_record() {
        let cancel = CancellationToken::new();
        let mut bytes = vec![b'x'; irmind_domain::SOURCE_MAX_BYTES + 10];
        bytes.extend_from_slice(b"\n\"bad quote\nnext\n");
        let mut input = std::io::Cursor::new(&bytes);
        let first = text_frame(&mut input, &cancel, bytes.len() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(first.0.len(), irmind_domain::SOURCE_MAX_BYTES + 1);
        assert_eq!(first.1, irmind_domain::SOURCE_MAX_BYTES as u64 + 11);
        assert_eq!(
            text_frame(&mut input, &cancel, 100).unwrap().unwrap().0,
            b"\"bad quote\n"
        );
        assert_eq!(
            text_frame(&mut input, &cancel, 100).unwrap().unwrap().0,
            b"next\n"
        );
    }
}
