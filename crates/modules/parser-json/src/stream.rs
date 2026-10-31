use super::ParserProfile;
use super::{AppError, GraphRecord, Tainted, normalize_record, parse_record, sha256};
use irmind_app::{CancellationToken, ParseReport};
use irmind_domain::ParserLocation;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::cell::Cell;
use std::io::{self, BufRead, BufReader, Cursor, Read};
use std::rc::Rc;
use std::time::Instant;

const MAX_STREAM_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_STREAM_RECORDS: usize = 10_000_000;
const MAX_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 64;

struct CountingReader<R> {
    inner: R,
    bytes: Rc<Cell<u64>>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(output)?;
        self.bytes
            .set(self.bytes.get().saturating_add(count as u64));
        Ok(count)
    }
}

struct RecordLimitReader<R> {
    inner: R,
    record_bytes: Rc<Cell<usize>>,
    max_record_bytes: usize,
}

impl<R: Read> Read for RecordLimitReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let used = self.record_bytes.get();
        let remaining = self.max_record_bytes.saturating_sub(used);
        let allowed = output.len().min(remaining.saturating_add(1));
        let count = self.inner.read(&mut output[..allowed])?;
        if count > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JSON record exceeds size limit",
            ));
        }
        self.record_bytes.set(used + count);
        Ok(count)
    }
}

struct RecordSink<'a> {
    source: &'a str,
    evidence_hash: [u8; 32],
    cancel: &'a CancellationToken,
    emit: &'a mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    count: usize,
    max_records: usize,
    failure: Option<AppError>,
    profile: Option<&'a ParserProfile>,
    record_bytes: Option<Rc<Cell<usize>>>,
    byte_count: Option<Rc<Cell<u64>>>,
    record_offset: u64,
}

impl RecordSink<'_> {
    fn accept(&mut self, value: Value) -> Result<(), AppError> {
        validate_shape(&value)?;
        if self.count >= self.max_records {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::TooManyJSONRecords,
            )));
        }
        if self.count.is_multiple_of(256) && self.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let started = Instant::now();
        let mut record = parse_record(
            self.source,
            self.evidence_hash,
            self.count,
            &normalize_record(value),
        )?;
        if self.byte_count.is_some() {
            record = record.with_parser_location(
                ParserLocation::new(self.source, "parser-json", self.record_offset)
                    .map_err(|_| AppError::Policy("invalid parser source provenance".into()))?,
            );
        }
        if let Some(profile) = self.profile {
            profile.extraction(started.elapsed());
        }
        let started = Instant::now();
        let result = (self.emit)(record);
        if let Some(profile) = self.profile {
            profile.emit(started.elapsed());
        }
        result?;
        self.count += 1;
        Ok(())
    }

    fn reset_record_limit(&self) {
        if let Some(bytes) = &self.record_bytes {
            bytes.set(0);
        }
    }

    fn start_record(&mut self) {
        if let Some(bytes) = &self.byte_count {
            // serde_json may have peeked the first byte of the next value.
            self.record_offset = bytes.get().saturating_sub(1);
        }
    }

    fn start_array_record(&mut self, first: bool) {
        if let Some(bytes) = &self.byte_count {
            // SeqAccess has consumed `[` before the first element and `,`
            // before later elements. Keep the cursor at that framing boundary.
            self.record_offset = bytes.get().saturating_add(u64::from(!first));
        }
    }

    fn accept_json<E: de::Error>(&mut self, value: Value) -> Result<(), E> {
        if let Err(error) = self.accept(value) {
            self.failure = Some(error);
            return Err(E::custom("JSON record rejected"));
        }
        Ok(())
    }
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
    if !walk(value, 0, &mut 0) {
        return Err(AppError::Policy(
            "JSON record exceeds field or depth limit".into(),
        ));
    }
    Ok(())
}

/// Reads a line while retaining at most one record's worth of bytes. The
/// remainder of an oversized line is consumed so following records survive.
fn bounded_line(reader: &mut impl BufRead) -> Result<(Vec<u8>, u64), AppError> {
    let mut line = Vec::new();
    let mut total = 0u64;
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| AppError::Policy("cannot read JSON line".into()))?;
        if available.is_empty() {
            break;
        }
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        let had_newline = available.get(end.saturating_sub(1)) == Some(&b'\n');
        let room = MAX_STREAM_RECORD_BYTES
            .saturating_add(1)
            .saturating_sub(line.len());
        line.extend_from_slice(&available[..end.min(room)]);
        total = total.saturating_add(end as u64);
        reader.consume(end);
        if had_newline {
            break;
        }
    }
    Ok((line, total))
}

fn record_sample(line: &[u8]) -> String {
    String::from_utf8_lossy(&line[..line.len().min(256)])
        .chars()
        .flat_map(char::escape_default)
        .take(256)
        .collect()
}

pub(super) fn parse_reader_report(
    source: &str,
    reader: &mut dyn Read,
    evidence_hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut buffered = BufReader::new(reader);
    let (first, first_len) = bounded_line(&mut buffered)?;
    let explicitly_lines = std::path::Path::new(source)
        .extension()
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("jsonl") || extension.eq_ignore_ascii_case("ndjson")
        });
    let first_value = (first.len() <= MAX_STREAM_RECORD_BYTES)
        .then(|| serde_json::from_slice::<Value>(&first).ok())
        .flatten();
    let record_object = first_value
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|object| {
            !["Records", "records", "events"]
                .iter()
                .any(|field| object.get(*field).is_some_and(Value::is_array))
        });
    if !explicitly_lines && (!record_object || !first.ends_with(b"\n")) {
        let accepted = parse_reader(
            source,
            &mut Cursor::new(first).chain(buffered),
            evidence_hash,
            cancel,
            emit,
        )?;
        return Ok(ParseReport {
            accepted,
            rejected: 0,
            samples: Vec::new(),
        });
    }
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    let mut offset = 0u64;
    let mut pending = Some((first, first_len));
    for row in 0..MAX_STREAM_RECORDS {
        if row.is_multiple_of(256) && cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (line, consumed) = pending
            .take()
            .map_or_else(|| bounded_line(&mut buffered), Ok)?;
        if consumed == 0 {
            return Ok(report);
        }
        if !line.iter().all(u8::is_ascii_whitespace) {
            let candidate = (line.len() <= MAX_STREAM_RECORD_BYTES)
                .then(|| serde_json::from_slice::<Value>(&line).ok())
                .flatten();
            let record = candidate.and_then(|value| {
                validate_shape(&value).ok()?;
                parse_record(
                    source,
                    evidence_hash,
                    report.accepted,
                    &normalize_record(value),
                )
                .ok()
            });
            if let Some(record) = record {
                let location = ParserLocation::new(source, "parser-json", offset)
                    .map_err(|_| AppError::Policy("invalid parser source provenance".into()))?;
                emit(record.with_parser_location(location))?;
                report.accepted += 1;
            } else {
                report.rejected = report.rejected.saturating_add(1);
                if report.samples.len() < 3 {
                    report.samples.push(record_sample(&line));
                }
            }
        }
        offset = offset.saturating_add(consumed);
    }
    Err(AppError::Policy(
        "JSON source exceeds record count limit".into(),
    ))
}

struct Root<'a, 'b>(&'a mut RecordSink<'b>);

impl<'de> DeserializeSeed<'de> for Root<'_, '_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(RootVisitor(self.0))
    }
}

struct RootVisitor<'a, 'b>(&'a mut RecordSink<'b>);

impl<'de> Visitor<'de> for RootVisitor<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object or array")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<(), S::Error> {
        let mut first = true;
        loop {
            self.0.reset_record_limit();
            self.0.start_array_record(first);
            let Some(value) = seq.next_element::<Value>()? else {
                break;
            };
            self.0.accept_json(value)?;
            first = false;
        }
        Ok(())
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        let mut object = Map::new();
        let mut wrapped = false;
        while let Some(key) = map.next_key::<String>()? {
            if matches!(key.as_str(), "Records" | "records" | "events") {
                if wrapped {
                    return Err(de::Error::custom("multiple JSON record arrays"));
                }
                map.next_value_seed(RecordArray(self.0))?;
                wrapped = true;
            } else {
                object.insert(key, map.next_value::<Value>()?);
            }
        }
        if !wrapped {
            self.0.accept_json(Value::Object(object))?;
        }
        Ok(())
    }
}

struct RecordArray<'a, 'b>(&'a mut RecordSink<'b>);

impl<'de> DeserializeSeed<'de> for RecordArray<'_, '_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(RootVisitor(self.0))
    }
}

pub(super) fn parse_each(
    source: &str,
    bytes: &[u8],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    profile: Option<&ParserProfile>,
) -> Result<usize, AppError> {
    let total_started = Instant::now();
    let hash_started = Instant::now();
    let evidence_hash = sha256(bytes);
    if let Some(profile) = profile {
        profile.hash(hash_started.elapsed());
    }
    let mut sink = RecordSink {
        source,
        evidence_hash,
        cancel,
        emit,
        count: 0,
        max_records: 100_000,
        failure: None,
        profile,
        record_bytes: None,
        byte_count: None,
        record_offset: 0,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    loop {
        if let Err(error) = Root(&mut sink).deserialize(&mut deserializer) {
            return Err(sink
                .failure
                .take()
                .unwrap_or_else(|| AppError::Storage(format!("invalid JSON record: {error}"))));
        }
        if deserializer.end().is_ok() {
            break;
        }
    }
    if let Some(profile) = profile {
        profile.total(total_started.elapsed());
    }
    Ok(sink.count)
}

pub(super) fn parse_reader(
    source: &str,
    reader: &mut dyn Read,
    evidence_hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<usize, AppError> {
    let record_bytes = Rc::new(Cell::new(0));
    let byte_count = Rc::new(Cell::new(0));
    let bounded = RecordLimitReader {
        inner: CountingReader {
            inner: BufReader::new(reader),
            bytes: Rc::clone(&byte_count),
        },
        record_bytes: Rc::clone(&record_bytes),
        max_record_bytes: MAX_STREAM_RECORD_BYTES,
    };
    let mut sink = RecordSink {
        source,
        evidence_hash,
        cancel,
        emit,
        count: 0,
        max_records: MAX_STREAM_RECORDS,
        failure: None,
        profile: None,
        record_bytes: Some(record_bytes),
        byte_count: Some(byte_count),
        record_offset: 0,
    };
    let mut deserializer = serde_json::Deserializer::from_reader(bounded);
    loop {
        sink.reset_record_limit();
        sink.start_record();
        if let Err(error) = Root(&mut sink).deserialize(&mut deserializer) {
            return Err(sink
                .failure
                .take()
                .unwrap_or_else(|| AppError::Storage(format!("invalid JSON record: {error}"))));
        }
        if deserializer.end().is_ok() {
            break;
        }
    }
    Ok(sink.count)
}
