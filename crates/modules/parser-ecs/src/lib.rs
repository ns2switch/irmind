#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted, UtcTimestamp};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Cursor, Read};

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;
const MAX_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 64;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;

pub struct EcsParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-ecs",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[],
};

impl Module for EcsParser {
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

impl LogParser for EcsParser {
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let first = sample.split(|byte| *byte == b'\n').next()?;
        let value: Value = serde_json::from_slice(&first[..first.len().min(64 * 1024)]).ok()?;
        let confidence =
            if field(&value, "/@timestamp").is_some() && field(&value, "/ecs/version").is_some() {
                95
            } else if field(&value, "/@timestamp").is_some()
                && field(&value, "/event/kind").is_some()
                && field(&value, "/host/name").is_some()
            {
                85
            } else {
                return None;
            };
        ParserConfidence::new(confidence).ok()
    }
}

impl EventParser for EcsParser {
    fn version(&self) -> &'static str {
        "ecs-ndjson-v1"
    }

    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(policy_error("ECS buffer exceeds 50 MiB"));
        }
        Ok(self
            .parse_reader_report(source, &mut Cursor::new(bytes), [0; 32], cancel, emit)?
            .accepted)
    }
}

impl StreamingEventParser for EcsParser {
    fn parser_name(&self) -> &'static str {
        "parser-ecs"
    }

    fn streaming_version(&self) -> &'static str {
        "ecs-ndjson-v1"
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
        let (line, consumed) = bounded_line(&mut reader)?;
        if consumed == 0 {
            return Ok(report);
        }
        if index >= MAX_RECORDS {
            return Err(policy_error("ECS source exceeds record limit"));
        }
        let current = offset;
        offset = offset.saturating_add(consumed);
        if offset > MAX_SOURCE_BYTES {
            return Err(policy_error("ECS source exceeds 50 GiB"));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            index += 1;
            continue;
        }
        if line.len() > MAX_RECORD_BYTES {
            reject(&mut report, &line);
            index += 1;
            continue;
        }
        let parsed = serde_json::from_slice::<Value>(&line)
            .map_err(|_| policy_error("invalid ECS JSON"))
            .and_then(|value| parse_record(index, &value));
        match parsed {
            Ok(record) => {
                let location = ParserLocation::new(source, "parser-ecs", current)
                    .map_err(|_| policy_error("invalid ECS source path"))?;
                let record = Tainted::from_external(
                    record,
                    Provenance::new(evidence_hash, Some(index as u64), SourceKind::File),
                )
                .with_parser_location(location);
                emit(record)?;
                report.accepted += 1;
            }
            Err(_) => reject(&mut report, &line),
        }
        index += 1;
    }
}

fn bounded_line(reader: &mut impl BufRead) -> Result<(Vec<u8>, u64), AppError> {
    let mut line = Vec::new();
    let mut consumed = 0u64;
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| policy_error("cannot read ECS source"))?;
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

fn parse_record(index: usize, value: &Value) -> Result<GraphRecord, AppError> {
    validate_shape(value)?;
    let at = timestamp(
        field(value, "/@timestamp").ok_or_else(|| policy_error("ECS timestamp is missing"))?,
    )?;
    if field(value, "/ecs/version").is_none() && field(value, "/event/kind").is_none() {
        return Err(policy_error("ECS markers are missing"));
    }
    let event = field(value, "/event/action")
        .or_else(|| field(value, "/event/category/0"))
        .unwrap_or("record");
    let mut entities = Vec::new();
    for (kind, path) in [
        ("host", "/host/name"),
        ("user", "/user/name"),
        ("process", "/process/name"),
        ("command_line", "/process/command_line"),
        ("ip", "/source/ip"),
        ("ip", "/destination/ip"),
        ("port", "/source/port"),
        ("port", "/destination/port"),
        ("file", "/file/path"),
        ("url", "/url/full"),
    ] {
        if let Some(value) = scalar(value.pointer(path))
            && !value.is_empty()
            && value.len() <= 4096
        {
            entities.push((kind.into(), value));
        }
    }
    entities.sort();
    entities.dedup();
    let normalized = json!({
        "at": at, "action": event, "result": field(value, "/event/outcome"),
        "host": field(value, "/host/name"), "user": field(value, "/user/name"),
        "process": field(value, "/process/name"), "command_line": field(value, "/process/command_line"),
        "source_ip": field(value, "/source/ip"), "source_port": value.pointer("/source/port"),
        "destination_ip": field(value, "/destination/ip"), "destination_port": value.pointer("/destination/port"),
        "file": field(value, "/file/path"), "url": field(value, "/url/full"),
        "attributes": value,
    });
    Ok(GraphRecord {
        index,
        at,
        event: event.into(),
        text: normalized.to_string(),
        entities,
        relations: Vec::new(),
    })
}

fn validate_shape(value: &Value) -> Result<(), AppError> {
    fn walk(value: &Value, depth: usize, fields: &mut usize) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        match value {
            Value::Object(object) => {
                *fields = fields.saturating_add(object.len());
                *fields <= MAX_FIELDS && object.values().all(|item| walk(item, depth + 1, fields))
            }
            Value::Array(array) => array.iter().all(|item| walk(item, depth + 1, fields)),
            _ => true,
        }
    }
    if walk(value, 0, &mut 0) {
        Ok(())
    } else {
        Err(policy_error("ECS record exceeds depth or field limit"))
    }
}

fn field<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    value.pointer(path).and_then(Value::as_str)
}

fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn timestamp(raw: &str) -> Result<String, AppError> {
    let parsed =
        DateTime::parse_from_rfc3339(raw).map_err(|_| policy_error("ECS timestamp is invalid"))?;
    let normalized = parsed
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    UtcTimestamp::parse(&normalized).map_err(|_| policy_error("ECS timestamp is out of range"))?;
    Ok(normalized)
}

fn policy_error(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecs_detects_and_maps_synthetic_record() -> Result<(), AppError> {
        let input = br#"{"@timestamp":"2026-01-02T03:04:05.500+01:00","ecs":{"version":"8.0"},"event":{"action":"process_start","outcome":"success"},"host":{"name":"lab-host"},"user":{"name":"alice"},"process":{"name":"bash","command_line":"echo test"},"source":{"ip":"192.0.2.1","port":1234},"destination":{"ip":"198.51.100.2","port":443},"file":{"path":"/tmp/example"},"url":{"full":"https://example.invalid/"},"custom":{"value":"retained"}}"#;
        assert_eq!(
            EcsParser
                .detect("sample.ndjson", input)
                .map(ParserConfidence::value),
            Some(95)
        );
        let mut records = Vec::new();
        let count = EcsParser.parse_each(
            "sample.ndjson",
            input,
            &CancellationToken::new(),
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )?;
        assert_eq!(count, 1);
        records[0].inspect(|record| {
            assert_eq!(record.at, "2026-01-02T02:04:05Z");
            assert!(
                record
                    .entities
                    .contains(&("host".into(), "lab-host".into()))
            );
            assert!(record.text.contains("retained"));
        });
        Ok(())
    }

    #[test]
    fn malformed_line_is_counted_and_later_record_survives() -> Result<(), AppError> {
        let good = b"{\"@timestamp\":\"2026-01-02T03:04:05Z\",\"ecs\":{\"version\":\"8.0\"}}\n";
        let input = [b"{broken}\n".as_slice(), good].concat();
        let mut records = Vec::new();
        let report = EcsParser.parse_reader_report(
            "sample.ndjson",
            &mut Cursor::new(input),
            [7; 32],
            &CancellationToken::new(),
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )?;
        assert_eq!((report.accepted, report.rejected), (1, 1));
        assert_eq!(records.len(), 1);
        Ok(())
    }

    #[test]
    fn excessive_depth_is_rejected_without_losing_next_record() -> Result<(), AppError> {
        let mut deep = json!({"leaf": "synthetic"});
        for _ in 0..65 {
            deep = json!({"nested": deep});
        }
        let bad = json!({
            "@timestamp": "2026-01-02T03:04:05Z",
            "ecs": {"version": "8.0"},
            "extra": deep
        });
        let good = json!({"@timestamp": "2026-01-02T03:04:05Z", "ecs": {"version": "8.0"}});
        let input = format!("{bad}\n{good}\n");
        let report = EcsParser.parse_reader_report(
            "sample.ndjson",
            &mut Cursor::new(input),
            [3; 32],
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (1, 1));
        Ok(())
    }
}
