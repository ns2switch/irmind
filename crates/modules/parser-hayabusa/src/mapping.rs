use chrono::{DateTime, Utc};
use irmind_app::{AppError, GraphRecord, GraphRelation};
use irmind_domain::UtcTimestamp;
use serde::Deserialize;

#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, rename = "Timestamp")]
    timestamp: Option<&'a str>,
    #[serde(borrow, rename = "RuleTitle")]
    rule_title: Option<&'a str>,
    #[serde(borrow, rename = "Level")]
    level: Option<&'a str>,
    #[serde(borrow, rename = "Computer")]
    computer: Option<&'a str>,
    #[serde(borrow, rename = "Channel")]
    channel: Option<&'a str>,
    #[serde(borrow, rename = "Details")]
    details: Option<&'a str>,
    #[serde(rename = "EventID")]
    event_id: Option<u64>,
}

pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let first = sample.split(|b| *b == b'\n').next()?;
    if first.starts_with(b"Timestamp,")
        && first.windows(9).any(|w| w == b"RuleTitle")
        && first.windows(8).any(|w| w == b"Computer")
    {
        return Some(95);
    }
    let row: Row<'_> = serde_json::from_slice(first).ok()?;
    if row.timestamp.is_some() && row.rule_title.is_some() && row.computer.is_some() {
        Some(95)
    } else {
        None
    }
}

pub(super) fn parse(line: &[u8], index: usize) -> Result<GraphRecord, AppError> {
    let row: Row<'_> = serde_json::from_slice(line).map_err(|_| bad())?;
    make_record(index, &row, String::from_utf8_lossy(line).into_owned())
}

pub(super) fn parse_csv(
    index: usize,
    headers: &csv::StringRecord,
    row: &csv::StringRecord,
) -> Result<GraphRecord, AppError> {
    let field = |name: &str| {
        headers
            .iter()
            .position(|h| h == name)
            .and_then(|i| row.get(i))
    };
    let fields = Row {
        timestamp: field("Timestamp"),
        rule_title: field("RuleTitle"),
        level: field("Level"),
        computer: field("Computer"),
        channel: field("Channel"),
        details: field("Details"),
        event_id: field("EventID").and_then(|value| value.parse().ok()),
    };
    let normalized = headers
        .iter()
        .zip(row.iter())
        .collect::<std::collections::BTreeMap<_, _>>();
    make_record(index, &fields, serde_json::json!(normalized).to_string())
}
fn make_record(index: usize, row: &Row<'_>, text: String) -> Result<GraphRecord, AppError> {
    let raw = row.timestamp.ok_or_else(bad)?;
    let parsed = DateTime::parse_from_rfc3339(raw)
        .or_else(|_| DateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f %:z"))
        .map_err(|_| bad())?;
    let at = parsed
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    UtcTimestamp::parse(&at).map_err(|_| bad())?;
    let mut entities = Vec::new();
    for (kind, value) in [
        ("host", row.computer),
        ("channel", row.channel),
        ("severity", row.level),
        ("rule", row.rule_title),
        ("detail", row.details),
    ] {
        if let Some(value) = value.filter(|text| !text.is_empty() && text.len() <= 4096) {
            entities.push((kind.into(), value.into()));
        }
    }
    let event = row.event_id.map_or_else(
        || "hayabusa_source_event".into(),
        |id| format!("windows_event_{id}"),
    );
    let mut relations = Vec::new();
    if let Some(rule) = row
        .rule_title
        .filter(|value| !value.is_empty() && value.len() <= 4096)
    {
        entities.push(("finding".into(), rule.into()));
        relations.push(GraphRelation {
            from_kind: "event".into(),
            from_value: event.clone(),
            relation: "detected_by".into(),
            to_kind: "finding".into(),
            to_value: rule.into(),
        });
    }
    entities.sort();
    entities.dedup();
    Ok(GraphRecord {
        index,
        at,
        event,
        text,
        entities,
        relations,
    })
}
fn bad() -> AppError {
    AppError::Policy("invalid Hayabusa timeline row".into())
}
