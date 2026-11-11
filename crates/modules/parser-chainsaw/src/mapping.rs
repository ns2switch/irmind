use serde::Deserialize;

// Borrowed columns retain the detector's input-type checks. Underscored
// columns are validated by deserialization and never normalized here.
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, alias = "Rule", alias = "rule")]
    rule: Option<&'a str>,
    #[serde(rename = "group", borrow)]
    _group: Option<&'a str>,
    #[serde(borrow)]
    kind: Option<&'a str>,
    #[serde(borrow, alias = "Timestamp", alias = "timestamp")]
    timestamp: Option<&'a str>,
    #[serde(rename = "computer", borrow, alias = "Computer", alias = "computer")]
    _computer: Option<&'a str>,
    #[serde(rename = "user", borrow, alias = "User", alias = "user")]
    _user: Option<&'a str>,
    #[serde(borrow, rename = "Event")]
    event: Option<Event<'a>>,
    #[serde(borrow)]
    document: Option<Document<'a>>,
}
#[derive(Deserialize)]
struct Document<'a> {
    #[serde(rename = "data", borrow)]
    _data: Option<DocumentData<'a>>,
}
#[derive(Deserialize)]
struct DocumentData<'a> {
    #[serde(borrow, rename = "Event")]
    _event: Option<Event<'a>>,
}
#[derive(Deserialize)]
struct Event<'a> {
    #[serde(borrow, rename = "System")]
    _system: Option<System<'a>>,
    #[serde(borrow, rename = "EventData")]
    _data: Option<EventData<'a>>,
}
#[derive(Deserialize)]
struct System<'a> {
    #[serde(borrow, rename = "Computer")]
    _computer: Option<&'a str>,
    #[serde(rename = "TimeCreated")]
    _time: Option<Time<'a>>,
    #[serde(rename = "EventID")]
    _event_id: Option<u64>,
}
#[derive(Deserialize)]
struct EventData<'a> {
    #[serde(borrow, rename = "SubjectUserName")]
    _user: Option<&'a str>,
    #[serde(borrow, rename = "NewProcessName")]
    _process: Option<&'a str>,
}
#[derive(Deserialize)]
struct Time<'a> {
    #[serde(borrow, rename = "SystemTime")]
    _system_time: Option<&'a str>,
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
