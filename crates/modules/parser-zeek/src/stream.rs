use irmind_app::{AppError, CancellationToken};
use std::io::BufRead;

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_FIELDS: usize = 1024;

#[derive(Clone, Default)]
pub(super) struct TsvHeader {
    pub(super) path: Option<String>,
    pub(super) fields: Vec<String>,
    pub(super) types: Vec<String>,
    types_seen: bool,
}

impl TsvHeader {
    pub(super) fn metadata(&mut self, line: &[u8]) -> Result<bool, AppError> {
        if line.starts_with(b"#separator ") {
            if line.trim_ascii() != b"#separator \\x09" {
                return Err(policy("unsupported Zeek field separator"));
            }
            return Ok(true);
        }
        if let Some(rest) = line.strip_prefix(b"#path\t") {
            let path =
                std::str::from_utf8(rest.trim_ascii()).map_err(|_| policy("invalid Zeek path"))?;
            if path.is_empty()
                || path.len() > 32
                || !path
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err(policy("invalid Zeek path"));
            }
            self.path = Some(path.into());
            return Ok(true);
        }
        if let Some(rest) = line.strip_prefix(b"#fields\t") {
            self.fields = split_header(rest)?;
            return Ok(true);
        }
        if let Some(rest) = line.strip_prefix(b"#types\t") {
            self.types = split_header(rest)?;
            self.types_seen = self.types.len() == self.fields.len();
            if !self.types_seen {
                return Err(policy("Zeek field and type counts differ"));
            }
            return Ok(true);
        }
        Ok([
            b"#set_separator".as_slice(),
            b"#empty_field".as_slice(),
            b"#unset_field".as_slice(),
            b"#open".as_slice(),
            b"#close".as_slice(),
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix)))
    }

    pub(super) fn ready(&self) -> bool {
        self.path.is_some() && !self.fields.is_empty() && self.types_seen
    }
}

fn split_header(bytes: &[u8]) -> Result<Vec<String>, AppError> {
    let text =
        std::str::from_utf8(bytes.trim_ascii()).map_err(|_| policy("invalid Zeek header"))?;
    let fields = text.split('\t').map(str::to_owned).collect::<Vec<_>>();
    if fields.is_empty()
        || fields.len() > MAX_FIELDS
        || fields
            .iter()
            .any(|field| field.is_empty() || field.len() > 128)
    {
        return Err(policy("Zeek header exceeds field limit"));
    }
    Ok(fields)
}

pub(super) fn bounded_line(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut line = Vec::new();
    let mut consumed = 0_u64;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let available = reader
            .fill_buf()
            .map_err(|_| policy("cannot read Zeek source"))?;
        if available.is_empty() {
            return Ok((line, consumed));
        }
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |pos| pos + 1);
        let newline = available[end - 1] == b'\n';
        let room = MAX_RECORD_BYTES
            .saturating_add(1)
            .saturating_sub(line.len());
        line.extend_from_slice(&available[..end.min(room)]);
        consumed = consumed
            .checked_add(end as u64)
            .ok_or_else(|| policy("parser source size overflow"))?;
        if consumed > MAX_SOURCE_BYTES {
            return Err(policy("parser source exceeds 50 GiB"));
        }
        reader.consume(end);
        if newline {
            return Ok((line, consumed));
        }
    }
}

fn policy(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}
