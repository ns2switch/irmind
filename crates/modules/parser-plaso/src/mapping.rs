use chrono::{DateTime, Utc};
use irmind_app::{AppError, GraphRecord};
use irmind_domain::UtcTimestamp;
use serde::Deserialize;

#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow)]
    datetime: Option<&'a str>,
    timestamp: Option<i64>,
    #[serde(borrow)]
    parser: Option<&'a str>,
    #[serde(borrow)]
    data_type: Option<&'a str>,
    #[serde(borrow)]
    user: Option<&'a str>,
    #[serde(borrow)]
    hostname: Option<&'a str>,
    #[serde(borrow)]
    filename: Option<&'a str>,
    #[serde(borrow)]
    source_short: Option<&'a str>,
}

pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let first = sample.split(|byte| *byte == b'\n').next()?;
    let row: Row<'_> = serde_json::from_slice(first).ok()?;
    if row.parser.is_some()
        && row.data_type.is_some()
        && (row.datetime.is_some() || row.timestamp.is_some())
    {
        Some(95)
    } else {
        None
    }
}
pub(super) fn parse(line: &[u8], index: usize) -> Result<GraphRecord, AppError> {
    let row: Row<'_> = serde_json::from_slice(line).map_err(|_| bad())?;
    let parsed = if let Some(datetime) = row.datetime {
        DateTime::parse_from_rfc3339(datetime)
            .map_err(|_| bad())?
            .with_timezone(&Utc)
    } else {
        DateTime::from_timestamp_micros(row.timestamp.ok_or_else(bad)?).ok_or_else(bad)?
    };
    let at = parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    UtcTimestamp::parse(&at).map_err(|_| bad())?;
    let mut entities = Vec::new();
    for (kind, value) in [
        ("host", row.hostname),
        ("user", row.user),
        ("file", row.filename),
        ("source", row.source_short),
    ] {
        if let Some(value) = value.filter(|text| !text.is_empty() && text.len() <= 4096) {
            entities.push((kind.into(), value.into()));
        }
    }
    entities.sort();
    entities.dedup();
    let event = row.data_type.or(row.parser).ok_or_else(bad)?;
    Ok(GraphRecord {
        index,
        at,
        event: event.into(),
        text: String::from_utf8_lossy(line).into_owned(),
        entities,
        relations: Vec::new(),
    })
}
fn bad() -> AppError {
    AppError::Policy("invalid plaso json_line result".into())
}
