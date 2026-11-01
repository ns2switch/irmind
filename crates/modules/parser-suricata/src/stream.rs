use crate::mapping;
use irmind_app::{AppError, CancellationToken, GraphRecord, ParseReport};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use std::io::{BufRead, BufReader, Read};

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 64;

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
    let mut offset = 0_u64;
    let mut index = 0_usize;
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
        if index >= MAX_RECORDS {
            return Err(policy("parser record limit exceeded"));
        }
        if line.len() > MAX_RECORD_BYTES || !bounded_json_shape(&line) {
            reject(&mut report, &line);
            index += 1;
            continue;
        }
        match mapping::parse(&line, index) {
            Ok(record) => {
                let location = ParserLocation::new(source, "parser-suricata", current)
                    .map_err(|_| policy("invalid parser source path"))?;
                emit(
                    Tainted::from_external(
                        record,
                        Provenance::new(hash, Some(index as u64), SourceKind::File),
                    )
                    .with_parser_location(location),
                )?;
                report.accepted += 1;
            }
            Err(_) => reject(&mut report, &line),
        }
        index += 1;
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
            .map_err(|_| policy("cannot read Suricata source"))?;
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
