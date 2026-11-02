use super::{AppError, CancellationToken, GraphRecord, ParseReport, SyslogParser, Tainted};
use irmind_domain::{ParserLocation, Provenance, SourceKind};
use std::io::{BufRead, BufReader, Read};

const MAX_LINE: usize = 1024 * 1024;
const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;

pub(super) fn parse(
    parser: &SyslogParser,
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
    let mut offset = 0;
    let mut index = 0;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (bytes, consumed) = frame(&mut reader, cancel)?;
        if consumed == 0 {
            break;
        }
        if index >= MAX_RECORDS || offset + consumed > MAX_SOURCE {
            return Err(super::limit());
        }
        if consumed > MAX_LINE as u64 || !bytes.iter().all(u8::is_ascii_whitespace) {
            let parsed = std::str::from_utf8(&bytes)
                .ok()
                .filter(|_| consumed <= MAX_LINE as u64)
                .and_then(|line| {
                    super::record::parse(line.trim_end_matches(['\r', '\n']), parser.legacy, index)
                        .ok()
                });
            if let Some(row) = parsed {
                let location = ParserLocation::new(source, "parser-syslog", offset)
                    .map_err(|_| super::limit())?;
                emit(
                    Tainted::from_external(
                        row,
                        Provenance::new(hash, Some(index as u64), SourceKind::File),
                    )
                    .with_parser_location(location),
                )?;
                report.accepted += 1;
            } else {
                report.rejected += 1;
                if report.samples.len() < 3 {
                    report
                        .samples
                        .push(String::from_utf8_lossy(&bytes).chars().take(64).collect());
                }
            }
            index += 1;
        }
        offset += consumed;
    }
    Ok(report)
}

fn frame(
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
