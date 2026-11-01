use chrono::{DateTime, Utc};
use irmind_app::{AppError, GraphRecord};
use irmind_domain::UtcTimestamp;
use serde::Deserialize;

#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, rename = "Timestamp", alias = "timestamp", alias = "Time")]
    timestamp: Option<&'a str>,
    #[serde(borrow, rename = "Artifact")]
    artifact: Option<&'a str>,
    #[serde(borrow, rename = "_Source")]
    source: Option<&'a str>,
    #[serde(borrow, rename = "Host", alias = "Hostname")]
    host: Option<&'a str>,
    #[serde(borrow, rename = "User", alias = "Username")]
    user: Option<&'a str>,
    #[serde(borrow, rename = "Process", alias = "Image")]
    process: Option<&'a str>,
    #[serde(borrow, rename = "CommandLine")]
    command_line: Option<&'a str>,
    #[serde(borrow, rename = "SourceIP")]
    source_ip: Option<&'a str>,
    #[serde(borrow, rename = "DestinationIP")]
    destination_ip: Option<&'a str>,
    #[serde(borrow, rename = "EventName")]
    event: Option<&'a str>,
}

pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let first = sample.split(|byte| *byte == b'\n').next()?;
    let row: Row<'_> = serde_json::from_slice(first).ok()?;
    if row.artifact.is_some() && row.source.is_some() && row.timestamp.is_some() {
        Some(95)
    } else if row.artifact.is_some() && row.timestamp.is_some() {
        Some(80)
    } else {
        None
    }
}

pub(super) fn parse(line: &[u8], index: usize) -> Result<GraphRecord, AppError> {
    let row: Row<'_> = serde_json::from_slice(line).map_err(|_| bad())?;
    if row.artifact.is_none() && row.source.is_none() {
        return Err(bad());
    }
    let at = normalized_time(row.timestamp.ok_or_else(bad)?)?;
    let mut entities = Vec::new();
    for (kind, value) in [
        ("host", row.host),
        ("user", row.user),
        ("process", row.process),
        ("command_line", row.command_line),
        ("ip", row.source_ip),
        ("ip", row.destination_ip),
        ("artifact", row.artifact),
    ] {
        if let Some(value) = value.filter(|text| !text.is_empty() && text.len() <= 4096) {
            entities.push((kind.into(), value.into()));
        }
    }
    entities.sort();
    entities.dedup();
    Ok(GraphRecord {
        index,
        at,
        event: row
            .event
            .or(row.artifact)
            .unwrap_or("artifact_result")
            .into(),
        text: String::from_utf8_lossy(line).into_owned(),
        entities,
        relations: Vec::new(),
    })
}

fn normalized_time(raw: &str) -> Result<String, AppError> {
    let parsed = DateTime::parse_from_rfc3339(raw).map_err(|_| bad())?;
    let at = parsed
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    UtcTimestamp::parse(&at).map_err(|_| bad())?;
    Ok(at)
}
fn bad() -> AppError {
    AppError::Policy("invalid Velociraptor result".into())
}
