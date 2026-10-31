use crate::{policy_error, record};
use irmind_app::{AppError, CancellationToken, GraphRecord, ParseReport};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;

pub(super) fn parse(
    source: &str,
    reader: impl Read,
    evidence_hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    let mut offset = 0u64;
    let mut index = 0usize;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (mut line, consumed) = bounded_line(&mut reader)?;
        if consumed == 0 {
            return Ok(report);
        }
        let current = offset;
        offset = offset.saturating_add(consumed);
        if offset > MAX_SOURCE_BYTES {
            return Err(policy_error("OCSF source exceeds 50 GiB"));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if index >= MAX_RECORDS {
            return Err(policy_error("OCSF source exceeds record limit"));
        }
        if line.len() > MAX_RECORD_BYTES {
            reject(&mut report, &line);
            index += 1;
            continue;
        }
        let parsed = parse_json_value(&mut reader, &mut line, &mut offset)?;
        if line.len() > MAX_RECORD_BYTES {
            reject(&mut report, &line);
            index += 1;
            continue;
        }
        let Ok(parsed) = parsed else {
            reject(&mut report, &line);
            index += 1;
            continue;
        };
        let values = match parsed {
            Value::Array(values) => values,
            value => vec![value],
        };
        for value in values {
            if index >= MAX_RECORDS {
                return Err(policy_error("OCSF source exceeds record limit"));
            }
            if let Ok(record) = record::parse(index, &value) {
                let location = ParserLocation::new(source, "parser-ocsf", current)
                    .map_err(|_| policy_error("invalid OCSF source path"))?;
                emit(
                    Tainted::from_external(
                        record,
                        Provenance::new(evidence_hash, Some(index as u64), SourceKind::File),
                    )
                    .with_parser_location(location),
                )?;
                report.accepted += 1;
            } else {
                reject(&mut report, &line);
            }
            index += 1;
        }
    }
}

fn parse_json_value(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    offset: &mut u64,
) -> Result<Result<Value, serde_json::Error>, AppError> {
    let trimmed = line.trim_ascii();
    let multiline = trimmed == b"{" || trimmed == b"[";
    let mut parsed = serde_json::from_slice::<Value>(line);
    while multiline
        && parsed.as_ref().is_err_and(serde_json::Error::is_eof)
        && line.len() <= MAX_RECORD_BYTES
    {
        let (next, consumed) = bounded_line(reader)?;
        if consumed == 0 {
            break;
        }
        *offset = offset.saturating_add(consumed);
        if *offset > MAX_SOURCE_BYTES {
            return Err(policy_error("OCSF source exceeds 50 GiB"));
        }
        line.extend_from_slice(&next);
        parsed = serde_json::from_slice::<Value>(line);
    }
    Ok(parsed)
}

fn bounded_line(reader: &mut impl BufRead) -> Result<(Vec<u8>, u64), AppError> {
    let mut line = Vec::new();
    let mut consumed = 0u64;
    loop {
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
        reader.consume(end);
        if newline {
            return Ok((line, consumed));
        }
    }
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
