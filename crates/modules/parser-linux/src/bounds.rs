use super::{AppError, CancellationToken, bad};
use irmind_app::ParseReport;
use std::io::BufRead;
pub(super) const MAX_LINE: usize = 1024 * 1024;
pub(super) const MAX_RECORDS: usize = 10_000_000;
pub(super) const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;

pub(super) fn line(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut bytes = Vec::new();
    let mut consumed = 0;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let chunk = reader
            .fill_buf()
            .map_err(|_| bad("cannot read Linux source"))?;
        if chunk.is_empty() {
            return Ok((bytes, consumed));
        }
        let count = chunk
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(chunk.len(), |i| i + 1);
        let done = chunk[count - 1] == b'\n';
        bytes.extend_from_slice(&chunk[..count.min(MAX_LINE.saturating_sub(bytes.len()))]);
        reader.consume(count);
        consumed += count as u64;
        if consumed > MAX_SOURCE {
            return Err(bad("Linux line exceeds source size limit"));
        }
        if done {
            return Ok((bytes, consumed));
        }
    }
}
pub(super) fn json_shape(line: &[u8]) -> bool {
    let (mut depth, mut fields, mut quoted, mut escaped) = (0usize, 0usize, false, false);
    for &byte in line {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > 64 {
                    return false;
                }
            }
            b'}' | b']' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            b':' => {
                fields += 1;
                if fields > 1024 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !quoted
}
pub(super) fn reject(report: &mut ParseReport, bytes: &[u8]) {
    report.rejected += 1;
    if report.samples.len() < 3 {
        report.samples.push(
            String::from_utf8_lossy(&bytes[..bytes.len().min(256)])
                .chars()
                .flat_map(char::escape_default)
                .take(256)
                .collect(),
        );
    }
}
