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
    let parser = DeclarativeParser::from_toml(definition).unwrap();
    let mut rows = Vec::new();
    let report = parser
        .parse_source(
            "synthetic/events.log",
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
