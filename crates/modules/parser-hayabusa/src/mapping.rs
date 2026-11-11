use serde::Deserialize;

// Borrowed columns retain the detector's input-type checks. Underscored
// columns are validated by deserialization and never normalized here.
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, rename = "Timestamp")]
    timestamp: Option<&'a str>,
    #[serde(borrow, rename = "RuleTitle")]
    rule_title: Option<&'a str>,
    #[serde(borrow, rename = "Level")]
    _level: Option<&'a str>,
    #[serde(borrow, rename = "Computer")]
    computer: Option<&'a str>,
    #[serde(borrow, rename = "Channel")]
    _channel: Option<&'a str>,
    #[serde(borrow, rename = "Details")]
    _details: Option<&'a str>,
    #[serde(rename = "EventID")]
    _event_id: Option<u64>,
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
