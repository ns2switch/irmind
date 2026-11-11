use serde::Deserialize;

// Borrowed columns retain the detector's input-type checks. Underscored
// columns are validated by deserialization and never normalized here.
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, rename = "Timestamp", alias = "timestamp", alias = "Time")]
    timestamp: Option<&'a str>,
    #[serde(borrow, rename = "Artifact")]
    artifact: Option<&'a str>,
    #[serde(borrow, rename = "_Source")]
    source: Option<&'a str>,
    #[serde(borrow, rename = "Host", alias = "Hostname")]
    _host: Option<&'a str>,
    #[serde(borrow, rename = "User", alias = "Username")]
    _user: Option<&'a str>,
    #[serde(borrow, rename = "Process", alias = "Image")]
    _process: Option<&'a str>,
    #[serde(borrow, rename = "CommandLine")]
    _command_line: Option<&'a str>,
    #[serde(borrow, rename = "SourceIP")]
    _source_ip: Option<&'a str>,
    #[serde(borrow, rename = "DestinationIP")]
    _destination_ip: Option<&'a str>,
    #[serde(borrow, rename = "EventName")]
    _event: Option<&'a str>,
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
