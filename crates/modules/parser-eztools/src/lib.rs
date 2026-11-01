#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use std::io::{BufRead, BufReader, Cursor, Read};

mod mapping;
pub struct EztoolsParser;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_FIELDS: usize = 1024;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-eztools",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[],
};

impl Module for EztoolsParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_parser(self)
    }
}
impl LogParser for EztoolsParser {
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        mapping::detect(&sample[..sample.len().min(64 * 1024)])
            .and_then(|value| ParserConfidence::new(value).ok())
    }
}
impl EventParser for EztoolsParser {
    fn version(&self) -> &'static str {
        "eztools-csv-v1"
    }
    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(policy("parser buffer exceeds 50 MiB"));
        }
        Ok(self
            .parse_reader_report(source, &mut Cursor::new(bytes), [0; 32], cancel, emit)?
            .accepted)
    }
}
impl StreamingEventParser for EztoolsParser {
    fn parser_name(&self) -> &'static str {
        "parser-eztools"
    }
    fn streaming_version(&self) -> &'static str {
        "eztools-csv-v1"
    }
    fn parse_reader(
        &self,
        source: &str,
        reader: &mut dyn Read,
        evidence_hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Ok(self
            .parse_reader_report(source, reader, evidence_hash, cancel, emit)?
            .accepted)
    }
    fn parse_reader_report(
        &self,
        source: &str,
        reader: &mut dyn Read,
        evidence_hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        parse_lines(source, reader, evidence_hash, cancel, emit)
    }
}
fn parse_lines(
    source: &str,
    reader: &mut dyn Read,
    hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    parse_csv_lines(source, &mut reader, hash, cancel, emit)
}
fn bounded_line(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, u64, bool), AppError> {
    let mut line = Vec::new();
    let mut consumed = 0u64;
    let mut odd_quotes = false;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let available = reader
            .fill_buf()
            .map_err(|_| policy("cannot read parser source"))?;
        if available.is_empty() {
            return Ok((line, consumed, odd_quotes));
        }
        let end = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |p| p + 1);
        let newline = available[end - 1] == b'\n';
        odd_quotes ^= available[..end]
            .iter()
            .fold(false, |odd, byte| odd ^ (*byte == b'"'));
        let room = MAX_RECORD_BYTES
            .saturating_add(1)
            .saturating_sub(line.len());
        line.extend_from_slice(&available[..end.min(room)]);
        consumed = consumed.saturating_add(end as u64);
        if consumed > MAX_SOURCE_BYTES {
            return Err(policy("Eztools CSV source exceeds 50 GiB"));
        }
        reader.consume(end);
        if newline {
            return Ok((line, consumed, odd_quotes));
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
fn policy(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}

fn parse_csv_lines(
    source: &str,
    reader: &mut impl BufRead,
    hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let (header, consumed) = csv_record(reader, cancel)?;
    if consumed == 0 {
        return Err(policy("Eztools CSV header is missing"));
    }
    let headers = decode_csv(&header)?;
    if headers.len() > MAX_FIELDS || mapping::tool_for_headers(&headers).is_none() {
        return Err(policy("EZTools CSV header is invalid"));
    }
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    let mut offset = consumed;
    let mut index = 0usize;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (row_bytes, size) = csv_record(reader, cancel)?;
        if size == 0 {
            return Ok(report);
        }
        if index >= MAX_RECORDS {
            return Err(policy("Eztools CSV record limit exceeded"));
        }
        let current = offset;
        offset = offset.saturating_add(size);
        if offset > MAX_SOURCE_BYTES {
            return Err(policy("Eztools CSV source exceeds 50 GiB"));
        }
        if row_bytes.len() > MAX_RECORD_BYTES {
            reject(&mut report, &row_bytes);
            index += 1;
            continue;
        }
        let parsed = decode_csv(&row_bytes).and_then(|row| {
            if row.len() > MAX_FIELDS || row.len() != headers.len() {
                return Err(policy("Eztools CSV field limit exceeded"));
            }
            mapping::parse_csv(index, &headers, &row)
        });
        match parsed {
            Ok(record) => {
                let location = ParserLocation::new(source, "parser-eztools", current)
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
            Err(_) => reject(&mut report, &row_bytes),
        }
        index += 1;
    }
}
fn csv_record(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut record = Vec::new();
    let mut consumed = 0u64;
    let mut quote_parity = false;
    loop {
        let (line, size, line_odd_quotes) = bounded_line(reader, cancel)?;
        if size == 0 {
            return Ok((record, consumed));
        }
        consumed = consumed.saturating_add(size);
        if consumed > MAX_SOURCE_BYTES {
            return Err(policy("Eztools CSV source exceeds 50 GiB"));
        }
        record.extend_from_slice(
            &line[..line.len().min(
                MAX_RECORD_BYTES
                    .saturating_add(1)
                    .saturating_sub(record.len()),
            )],
        );
        quote_parity ^= line_odd_quotes;
        if !quote_parity {
            return Ok((record, consumed));
        }
    }
}
fn decode_csv(bytes: &[u8]) -> Result<csv::StringRecord, AppError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(bytes);
    let row = reader
        .records()
        .next()
        .ok_or_else(|| policy("empty CSV record"))?
        .map_err(|_| policy("invalid CSV record"))?;
    if reader.records().next().is_some() {
        return Err(policy("unexpected extra CSV record"));
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &[u8] =
        include_bytes!("../../../testkit/fixtures/parser-eztools/source/events.csv");
    #[test]
    fn bad_csv_row_is_rejected_without_losing_next() -> Result<(), AppError> {
        let text = std::str::from_utf8(FIXTURE).map_err(|_| policy("invalid fixture"))?;
        let (header, good) = text
            .split_once('\n')
            .ok_or_else(|| policy("invalid fixture"))?;
        let input = format!("{header}\n,cmd.exe,missing.pf,true\n{good}");
        let report = EztoolsParser.parse_reader_report(
            "sample.csv",
            &mut input.as_bytes(),
            [3; 32],
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (2, 1));
        Ok(())
    }
    #[test]
    fn oversized_multiline_csv_record_does_not_desynchronize_next_row() -> Result<(), AppError> {
        let text = std::str::from_utf8(FIXTURE).map_err(|_| policy("invalid fixture"))?;
        let (header, good) = text
            .split_once('\n')
            .ok_or_else(|| policy("invalid fixture"))?;
        let input = format!(
            "{header}\n\"{}\ncontinued\",cmd.exe,missing.pf,true\n{good}",
            "x".repeat(MAX_RECORD_BYTES)
        );
        let report = EztoolsParser.parse_reader_report(
            "sample.csv",
            &mut input.as_bytes(),
            [3; 32],
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (2, 1));
        Ok(())
    }
    #[test]
    fn cancellation_prevents_parsing() {
        let token = CancellationToken::new();
        token.cancel();
        let result = EztoolsParser.parse_reader_report(
            "sample",
            &mut &FIXTURE[..],
            [3; 32],
            &token,
            &mut |_| Ok(()),
        );
        assert!(matches!(result, Err(AppError::Cancelled)));
    }
    #[test]
    fn detects_and_parses_synthetic_episode() -> Result<(), AppError> {
        let parser = EztoolsParser;
        assert!(
            parser
                .detect("sample", FIXTURE)
                .is_some_and(ParserConfidence::is_high)
        );
        let mut records = Vec::new();
        let report = parser.parse_reader_report(
            "sample",
            &mut Cursor::new(FIXTURE),
            [7; 32],
            &CancellationToken::new(),
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )?;
        assert_eq!((report.accepted, report.rejected), (2, 0));
        assert_eq!(records.len(), 2);
        records[0].inspect(|record| assert_eq!(record.event, "PECmd timeline"));
        Ok(())
    }
}
