#![allow(clippy::unwrap_used)]

use super::*;
use irmind_app::{CancellationToken, GraphRecord, ParseReport};
use irmind_domain::Tainted;
use std::io::Cursor;

mod configuration;
mod parsing;

const SIMPLE: &str = r#"
version = 1
name = "simple"
description = "Synthetic event"
[input]
format = "ndjson"
[detect]
required_fields = ["/time"]
confidence = 70
[mapping]
time = "/time"
host = "/host"
action = "/action"
[timestamp]
format = "rfc3339"
default_timezone = "UTC"
"#;
const EVENT: &str = r#"{"time":"2026-10-23T10:00:00.123456789Z","host":"demo","action":"login"}"#;

fn parse(definition: &str, input: &str) -> (ParseReport, Vec<Tainted<GraphRecord>>) {
    let mut rows = Vec::new();
    let report = read(
        definition,
        &mut Cursor::new(input),
        [7; 32],
        &CancellationToken::new(),
        &mut |row| {
            rows.push(row);
            Ok(())
        },
    )
    .unwrap();
    (report, rows)
}

fn read(
    definition: &str,
    reader: &mut dyn std::io::Read,
    hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let pipeline = crate::pipeline::compile(definition)?;
    irmind_testkit::decode_source(
        pipeline.decoder().as_ref(),
        "synthetic/events.log",
        reader,
        hash,
        cancel,
        None,
        &mut |row| {
            let mut output = None;
            row.inspect(|record| {
                output = Some(pipeline.extraction_mapper().map(record));
            });
            let mapped = output
                .unwrap()
                .map_err(irmind_app::source_mapping::MappingError::into_app)?;
            emit(Tainted::from_external(
                mapped.record().indexed.record.clone(),
                row.provenance().clone(),
            ))
        },
    )
}
