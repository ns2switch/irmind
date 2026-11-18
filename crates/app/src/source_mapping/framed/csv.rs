//! Bounded RFC 4180 record framing shared by export decoders, never format detection.
use crate::{AppError, CancellationToken, FixedAppError};
use std::io::BufRead;
const MAX_BYTES: usize = irmind_domain::SOURCE_MAX_BYTES;
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
/// Retains at most one bounded record; byte count includes consumed line endings.
pub fn csv_frame(
    reader: &mut dyn BufRead,
    cancel: &CancellationToken,
    remaining: u64,
) -> Result<Option<(Vec<u8>, u64)>, AppError> {
    let mut out = Vec::new();
    let mut consumed = 0u64;
    let mut quoted = false;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let buf = reader.fill_buf().map_err(|_| invalid())?;
        if buf.is_empty() {
            return if consumed == 0 {
                Ok(None)
            } else {
                Ok(Some((out, consumed)))
            };
        }
        let mut used = 0;
        let mut done = false;
        for &b in buf {
            used += 1;
            consumed = consumed.checked_add(1).ok_or_else(invalid)?;
            if consumed > remaining {
                return Err(AppError::Fixed(FixedAppError::SourceLimit));
            }
            if out.len() <= MAX_BYTES {
                out.push(b);
            }
            if b == b'"' {
                quoted = !quoted;
            }
            if b == b'\n' && !quoted {
                done = true;
                break;
            }
        }
        reader.consume(used);
        if done {
            return Ok(Some((out, consumed)));
        }
    }
}
/// Strict fields: escaped quotes, embedded CRLF and UTF-8, without a second unbounded parser.
pub fn csv_values(input: &[u8]) -> Result<Vec<String>, AppError> {
    if input.len() > MAX_BYTES {
        return Err(AppError::Fixed(FixedAppError::SourceLimit));
    }
    let mut bytes = input;
    if bytes.ends_with(b"\n") {
        bytes = &bytes[..bytes.len() - 1];
        if bytes.ends_with(b"\r") {
            bytes = &bytes[..bytes.len() - 1];
        }
    }
    let mut fields = Vec::new();
    let mut field = Vec::new();
    let mut state = 0u8;
    for &b in bytes {
        match state {
            0 => match b {
                b'"' => state = 2,
                b',' => push(&mut fields, &mut field)?,
                b'\r' | b'\n' => return Err(invalid()),
                _ => {
                    field.push(b);
                    state = 1;
                }
            },
            1 => match b {
                b',' => {
                    push(&mut fields, &mut field)?;
                    state = 0;
                }
                b'"' | b'\r' | b'\n' => return Err(invalid()),
                _ => field.push(b),
            },
            2 => {
                if b == b'"' {
                    state = 3;
                } else {
                    field.push(b);
                }
            }
            3 => match b {
                b'"' => {
                    field.push(b);
                    state = 2;
                }
                b',' => {
                    push(&mut fields, &mut field)?;
                    state = 0;
                }
                _ => return Err(invalid()),
            },
            _ => return Err(invalid()),
        }
    }
    if state == 2 {
        return Err(invalid());
    }
    push(&mut fields, &mut field)?;
    Ok(fields)
}
fn push(out: &mut Vec<String>, field: &mut Vec<u8>) -> Result<(), AppError> {
    if out.len() >= 1024 {
        return Err(AppError::Fixed(FixedAppError::SourceLimit));
    }
    out.push(String::from_utf8(std::mem::take(field)).map_err(|_| invalid())?);
    Ok(())
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn quoted_multiline_and_real_offsets() {
        let bytes = b"a,b\r\n\"x\r\ny\",\"z\"\"t\"\r\nq,r\n";
        let mut reader = std::io::Cursor::new(bytes);
        let cancel = CancellationToken::new();
        let (_, first) = csv_frame(&mut reader, &cancel, 1024).unwrap().unwrap();
        assert_eq!(first, 5);
        let (row, size) = csv_frame(&mut reader, &cancel, 1024).unwrap().unwrap();
        assert_eq!(csv_values(&row).unwrap(), ["x\r\ny", "z\"t"]);
        assert_eq!(first + size, bytes.len() as u64 - 4);
        assert_eq!(
            csv_values(&csv_frame(&mut reader, &cancel, 1024).unwrap().unwrap().0).unwrap(),
            ["q", "r"]
        );
    }
    #[test]
    fn rejects_unclosed_quote_extra_data_and_source_overflow() {
        for b in [b"\"bad".as_slice(), b"\"x\"z,y", b"a\nb"] {
            assert!(csv_values(b).is_err());
        }
        assert!(
            csv_frame(
                &mut std::io::Cursor::new(b"abc\n"),
                &CancellationToken::new(),
                3
            )
            .is_err()
        );
    }
    #[test]
    fn oversized_row_is_bounded_and_next_row_survives() {
        let bytes = [vec![b'x'; MAX_BYTES + 99], b"\na,b\n".to_vec()].concat();
        let mut reader = std::io::Cursor::new(bytes);
        let cancel = CancellationToken::new();
        let (row, size) = csv_frame(&mut reader, &cancel, 10_000_000)
            .unwrap()
            .unwrap();
        assert_eq!(row.len(), MAX_BYTES + 1);
        assert_eq!(size, MAX_BYTES as u64 + 100);
        assert!(csv_values(&row).is_err());
        assert_eq!(
            csv_values(&csv_frame(&mut reader, &cancel, 1024).unwrap().unwrap().0).unwrap(),
            ["a", "b"]
        );
    }
}
