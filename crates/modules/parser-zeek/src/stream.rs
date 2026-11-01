use crate::mapping;
use irmind_app::{AppError, CancellationToken, GraphRecord, ParseReport};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use std::io::{BufRead, BufReader, Read};

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 64;

#[derive(Default)]
struct TsvHeader {
    path: Option<String>,
    fields: Vec<String>,
    types_seen: bool,
}

impl TsvHeader {
    fn metadata(&mut self, line: &[u8]) -> Result<bool, AppError> {
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
            self.types_seen = split_header(rest)?.len() == self.fields.len();
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

    fn ready(&self) -> bool {
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

pub(super) fn parse(
    source: &str,
    reader: &mut dyn Read,
    hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    let mut header = TsvHeader::default();
    let mut offset = 0_u64;
    let mut record_index = 0_usize;
    let mut is_tsv = None;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (line, consumed) = bounded_line(&mut reader, cancel)?;
        if consumed == 0 {
            return Ok(report);
        }
        let current = offset;
        offset = offset
            .checked_add(consumed)
            .ok_or_else(|| policy("parser source size overflow"))?;
        if offset > MAX_SOURCE_BYTES {
            return Err(policy("parser source exceeds 50 GiB"));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if line.len() > MAX_RECORD_BYTES {
            reject(&mut report, &line);
            record_index = record_index.saturating_add(1);
            continue;
        }
        let tsv = *is_tsv.get_or_insert_with(|| line.starts_with(b"#"));
        if tsv && header.metadata(&line)? {
            continue;
        }
        if record_index >= MAX_RECORDS {
            return Err(policy("parser record limit exceeded"));
        }
        let record = if tsv && header.ready() {
            mapping::from_tsv(
                header.path.as_deref().unwrap_or(""),
                &header.fields,
                &line,
                record_index,
            )
        } else if !tsv && bounded_json_shape(&line) {
            mapping::from_json(source, &line, record_index)
        } else {
            Err(policy("invalid Zeek record or missing header"))
        };
        match record {
            Ok(record) => {
                let location = ParserLocation::new(source, "parser-zeek", current)
                    .map_err(|_| policy("invalid parser source path"))?;
                emit(
                    Tainted::from_external(
                        record,
                        Provenance::new(hash, Some(record_index as u64), SourceKind::File),
                    )
                    .with_parser_location(location),
                )?;
                report.accepted += 1;
            }
            Err(_) => reject(&mut report, &line),
        }
        record_index += 1;
    }
}

fn bounded_line(
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

fn bounded_json_shape(line: &[u8]) -> bool {
    let (mut depth, mut fields, mut in_string, mut escaped) = (0_usize, 0_usize, false, false);
    for &byte in line {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_DEPTH {
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
                if fields > MAX_FIELDS {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_string
}

fn reject(report: &mut ParseReport, line: &[u8]) {
    report.rejected += 1;
    if report.samples.len() < 3 {
        report.samples.push(
            String::from_utf8_lossy(&line[..line.len().min(256)])
                .chars()
                .flat_map(char::escape_default)
                .take(256)
                .collect(),
        );
    }
}

fn policy(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}
