//! Iterative traversal only. MIME boundary lines do not contain executable syntax.
use crate::{invalid, limit};
use irmind_app::{AppError, CancellationToken};
#[derive(Clone, Copy)]
pub(super) struct Part {
    pub start: usize,
    pub end: usize,
    pub depth: usize,
}
pub(super) fn children(
    bytes: &[u8],
    body: usize,
    boundary: &str,
    depth: usize,
    cancel: &CancellationToken,
) -> Result<Vec<Part>, AppError> {
    if depth >= 16
        || boundary.is_empty()
        || boundary.len() > 70
        || boundary.ends_with(' ')
        || !boundary
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b))
    {
        return Err(limit());
    }
    let marker = format!("--{boundary}");
    let mut offset = body;
    let mut begin = None;
    let mut parts = Vec::new();
    let mut closed = false;
    for line in bytes[body..].split_inclusive(|b| *b == b'\n') {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let bare = trim(line);
        if let Some(rest) = bare.strip_prefix(marker.as_bytes())
            && (rest.is_empty() || rest == b"--")
        {
            if let Some(start) = begin.take() {
                let mut end = offset;
                if bytes[..end].ends_with(b"\r\n") {
                    end -= 2;
                } else if bytes[..end].ends_with(b"\n") {
                    end -= 1;
                }
                if end < start || parts.len() >= 256 {
                    return Err(limit());
                }
                parts.push(Part {
                    start,
                    end,
                    depth: depth + 1,
                });
            }
            if rest == b"--" {
                closed = true;
                break;
            }
            begin = Some(offset + line.len());
        }
        offset += line.len();
    }
    if !closed || parts.is_empty() {
        return Err(invalid());
    }
    Ok(parts)
}
fn trim(mut line: &[u8]) -> &[u8] {
    while line
        .last()
        .is_some_and(|b| matches!(*b, b'\r' | b'\n' | b' ' | b'\t'))
    {
        line = &line[..line.len() - 1];
    }
    line
}
