#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use std::io::{BufRead, BufReader, Cursor, Read};

mod csv;
mod mapping;
pub struct HayabusaParser;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 64;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-hayabusa",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[],
};

impl Module for HayabusaParser {
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
impl LogParser for HayabusaParser {
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        mapping::detect(&sample[..sample.len().min(64 * 1024)])
            .and_then(|value| ParserConfidence::new(value).ok())
    }
}
impl EventParser for HayabusaParser {
    fn version(&self) -> &'static str {
        "hayabusa-json-csv-v1"
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
impl StreamingEventParser for HayabusaParser {
    fn parser_name(&self) -> &'static str {
        "parser-hayabusa"
    }
    fn streaming_version(&self) -> &'static str {
        "hayabusa-json-csv-v1"
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
    if reader
        .fill_buf()
        .map_err(|_| policy("cannot read parser source"))?
        .starts_with(b"Timestamp,")
    {
        return csv::parse_csv_lines(source, &mut reader, hash, cancel, emit);
    }
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
        let (line, consumed, _) = bounded_line(&mut reader, cancel)?;
        if consumed == 0 {
            return Ok(report);
        }
        if index >= MAX_RECORDS {
            return Err(policy("parser record limit exceeded"));
        }
        let current = offset;
        offset = offset.saturating_add(consumed);
        if offset > MAX_SOURCE_BYTES {
            return Err(policy("parser source exceeds 50 GiB"));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            index += 1;
            continue;
        }
        if line.len() > MAX_RECORD_BYTES || !bounded_json_shape(&line) {
            reject(&mut report, &line);
            index += 1;
            continue;
        }
        match mapping::parse(&line, index) {
            Ok(record) => {
                let location = ParserLocation::new(source, "parser-hayabusa", current)
                    .map_err(|_| policy("invalid parser source path"))?;
                let tainted = Tainted::from_external(
                    record,
                    Provenance::new(hash, Some(index as u64), SourceKind::File),
                )
                .with_parser_location(location);
                emit(tainted)?;
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
            return Err(policy("Hayabusa source exceeds 50 GiB"));
        }
        reader.consume(end);
        if newline {
            return Ok((line, consumed, odd_quotes));
        }
    }
}
fn bounded_json_shape(line: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut fields = 0usize;
    let mut in_string = false;
    let mut escaped = false;
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

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &[u8] =
        include_bytes!("../../../testkit/fixtures/parser-hayabusa/source/events.jsonl");
    #[test]
    fn csv_timeline_is_parsed_with_explicit_offset() -> Result<(), AppError> {
        let input=b"Timestamp,RuleTitle,Level,Computer,Channel,Details\n2026-10-23 13:03:00.000 +01:00,Synthetic task,high,lab-host,Security,TaskName=DemoTask\n";
        assert!(HayabusaParser.detect("timeline.csv", input).is_some());
        let mut records = Vec::new();
        let report = HayabusaParser.parse_reader_report(
            "timeline.csv",
            &mut input.as_ref(),
            [3; 32],
            &CancellationToken::new(),
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )?;
        assert_eq!((report.accepted, report.rejected), (1, 0));
        records[0].inspect(|record| assert_eq!(record.at, "2026-10-23T12:03:00Z"));
        Ok(())
    }
    #[test]
    fn bad_record_is_rejected_without_losing_next() -> Result<(), AppError> {
        let mut input = b"{broken}\n".to_vec();
        input.extend_from_slice(FIXTURE);
        let report = HayabusaParser.parse_reader_report(
            "sample.jsonl",
            &mut input.as_slice(),
            [3; 32],
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (2, 1));
        assert!(!report.samples.is_empty());
        Ok(())
    }
    #[test]
    fn oversized_multiline_csv_record_does_not_desynchronize_next_row() -> Result<(), AppError> {
        let input = format!(
            "Timestamp,RuleTitle,Computer\n2026-10-23T12:00:00Z,\"{}\ncontinued\",host\n2026-10-23T12:01:00Z,Valid,host\n",
            "x".repeat(MAX_RECORD_BYTES)
        );
        let report = HayabusaParser.parse_reader_report(
            "timeline.csv",
            &mut input.as_bytes(),
            [3; 32],
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (1, 1));
        Ok(())
    }
    #[test]
    fn cancellation_prevents_parsing() {
        let token = CancellationToken::new();
        token.cancel();
        let result = HayabusaParser.parse_reader_report(
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
        let parser = HayabusaParser;
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
        records[0].inspect(|record| {
            assert_eq!(record.event, "windows_event_4698");
            assert!(
                record
                    .relations
                    .iter()
                    .any(|edge| edge.relation == "detected_by"
                        && edge.to_value == "Synthetic scheduled task")
            );
        });
        Ok(())
    }
}
