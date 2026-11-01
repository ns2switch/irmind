use chrono::{DateTime, Utc};
use irmind_app::{AppError, GraphRecord};
use irmind_domain::UtcTimestamp;
use serde::Deserialize;

#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, alias = "Rule", alias = "rule")]
    rule: Option<&'a str>,
    #[serde(borrow)]
    group: Option<&'a str>,
    #[serde(borrow)]
    kind: Option<&'a str>,
    #[serde(borrow, alias = "Timestamp", alias = "timestamp")]
    timestamp: Option<&'a str>,
    #[serde(borrow, alias = "Computer", alias = "computer")]
    computer: Option<&'a str>,
    #[serde(borrow, alias = "User", alias = "user")]
    user: Option<&'a str>,
    #[serde(borrow, rename = "Event")]
    event: Option<Event<'a>>,
    #[serde(borrow)]
    document: Option<Document<'a>>,
}
#[derive(Deserialize)]
struct Document<'a> {
    #[serde(borrow)]
    data: Option<DocumentData<'a>>,
}
#[derive(Deserialize)]
struct DocumentData<'a> {
    #[serde(borrow, rename = "Event")]
    event: Option<Event<'a>>,
}
#[derive(Deserialize)]
struct Event<'a> {
    #[serde(borrow, rename = "System")]
    system: Option<System<'a>>,
    #[serde(borrow, rename = "EventData")]
    data: Option<EventData<'a>>,
}
#[derive(Deserialize)]
struct System<'a> {
    #[serde(borrow, rename = "Computer")]
    computer: Option<&'a str>,
    #[serde(rename = "TimeCreated")]
    time: Option<Time<'a>>,
    #[serde(rename = "EventID")]
    event_id: Option<u64>,
}
#[derive(Deserialize)]
struct EventData<'a> {
    #[serde(borrow, rename = "SubjectUserName")]
    user: Option<&'a str>,
    #[serde(borrow, rename = "NewProcessName")]
    process: Option<&'a str>,
}
#[derive(Deserialize)]
struct Time<'a> {
    #[serde(borrow, rename = "SystemTime")]
    system_time: Option<&'a str>,
}

pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let first_nonspace = sample
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())?;
    if first_nonspace == b'[' {
        let has = |needle: &[u8]| sample.windows(needle.len()).any(|window| window == needle);
        return ((has(b"\"Rule\"") && has(b"\"Event\""))
            || (has(b"\"document\"") && has(b"\"kind\"")))
        .then_some(80);
    }
    let first = sample.split(|byte| *byte == b'\n').next()?;
    let row: Row<'_> = serde_json::from_slice(first).ok()?;
    if (row.document.is_some() && row.kind.is_some()) || (row.rule.is_some() && row.event.is_some())
    {
        Some(95)
    } else if row.rule.is_some() && row.timestamp.is_some() {
        Some(80)
    } else {
        None
    }
}

pub(super) fn parse(line: &[u8], index: usize) -> Result<GraphRecord, AppError> {
    let row: Row<'_> = serde_json::from_slice(line).map_err(|_| bad())?;
    let event = row
        .event
        .as_ref()
        .or_else(|| row.document.as_ref()?.data.as_ref()?.event.as_ref());
    let system = event.and_then(|event| event.system.as_ref());
    let data = event.and_then(|event| event.data.as_ref());
    let timestamp = row
        .timestamp
        .or_else(|| system?.time.as_ref()?.system_time)
        .ok_or_else(bad)?;
    let parsed = DateTime::parse_from_rfc3339(timestamp).map_err(|_| bad())?;
    let at = parsed
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    UtcTimestamp::parse(&at).map_err(|_| bad())?;
    let mut entities = Vec::new();
    for (kind, value) in [
        (
            "host",
            row.computer.or_else(|| system.and_then(|s| s.computer)),
        ),
        ("user", row.user.or_else(|| data.and_then(|d| d.user))),
        ("process", data.and_then(|d| d.process)),
        ("rule", row.rule.or(row.group)),
    ] {
        if let Some(value) = value.filter(|text| !text.is_empty() && text.len() <= 4096) {
            entities.push((kind.into(), value.into()));
        }
    }
    if let Some(id) = system.and_then(|s| s.event_id) {
        entities.push(("event_id".into(), id.to_string()));
    }
    entities.sort();
    entities.dedup();
    Ok(GraphRecord {
        index,
        at,
        event: row.rule.or(row.group).unwrap_or("chainsaw_match").into(),
        text: String::from_utf8_lossy(line).into_owned(),
        entities,
        relations: Vec::new(),
    })
}
fn bad() -> AppError {
    AppError::Policy("invalid Chainsaw result".into())
}
