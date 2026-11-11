use serde::Deserialize;

// Borrowed columns retain the detector's input-type checks. Underscored
// columns are validated by deserialization and never normalized here.
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow)]
    datetime: Option<&'a str>,
    timestamp: Option<i64>,
    #[serde(borrow)]
    parser: Option<&'a str>,
    #[serde(borrow)]
    data_type: Option<&'a str>,
    #[serde(rename = "user", borrow)]
    _user: Option<&'a str>,
    #[serde(rename = "hostname", borrow)]
    _hostname: Option<&'a str>,
    #[serde(rename = "filename", borrow)]
    _filename: Option<&'a str>,
    #[serde(rename = "source_short", borrow)]
    _source_short: Option<&'a str>,
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
