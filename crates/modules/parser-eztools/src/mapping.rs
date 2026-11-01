use chrono::{DateTime, NaiveDateTime, Utc};
use irmind_app::{AppError, GraphRecord};
use irmind_domain::UtcTimestamp;

// Match exact column names, never filename substrings. These signatures are
// intentionally narrow; unknown exports require analyst selection or a parser update.
const HEADERS: &[(&str, &[&str])] = &[
    (
        "PECmd",
        &["SourceFilename", "ExecutableName", "RunCount", "LastRun"],
    ),
    (
        "PECmd timeline",
        &[
            "RunTime",
            "ExecutableName",
            "SourceFilename",
            "PathValidated",
        ],
    ),
    (
        "AmcacheParser",
        &["FileKeyLastWriteTimestamp", "SHA1", "FullPath"],
    ),
    (
        "AppCompatCacheParser",
        &["LastModifiedTimeUTC", "Path", "Executed"],
    ),
    (
        "MFTECmd",
        &[
            "EntryNumber",
            "SequenceNumber",
            "ParentPath",
            "FileName",
            "Created0x10",
        ],
    ),
    (
        "LECmd",
        &[
            "SourceFile",
            "SourceCreated",
            "TargetCreated",
            "RelativePath",
            "WorkingDirectory",
        ],
    ),
    (
        "RECmd batch",
        &["HivePath", "KeyPath", "ValueName", "LastWriteTimestamp"],
    ),
    (
        "SrumECmd",
        &["SourceFile", "Application", "UserName", "Timestamp"],
    ),
    (
        "EvtxECmd",
        &["TimeCreated", "EventId", "Channel", "Computer"],
    ),
];

pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let first = sample.split(|b| *b == b'\n').next()?;
    let headers = decode(first).ok()?;
    tool_for_headers(&headers).map(|_| 95)
}
pub(super) fn tool_for_headers(headers: &csv::StringRecord) -> Option<&'static str> {
    HEADERS.iter().find_map(|(tool, required)| {
        required
            .iter()
            .all(|field| headers.iter().any(|header| header == *field))
            .then_some(*tool)
    })
}
fn decode(bytes: &[u8]) -> Result<csv::StringRecord, AppError> {
    csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(bytes)
        .records()
        .next()
        .ok_or_else(bad)?
        .map_err(|_| bad())
}
pub(super) fn parse_csv(
    index: usize,
    headers: &csv::StringRecord,
    row: &csv::StringRecord,
) -> Result<GraphRecord, AppError> {
    let tool = tool_for_headers(headers).ok_or_else(bad)?;
    let field = |name: &str| {
        headers
            .iter()
            .position(|header| header == name)
            .and_then(|i| row.get(i))
    };
    let raw = [
        "RunTime",
        "LastRun",
        "FileKeyLastWriteTimestamp",
        "LastModifiedTimeUTC",
        "Created0x10",
        "SourceCreated",
        "LastWriteTimestamp",
        "Timestamp",
        "TimeCreated",
    ]
    .iter()
    .find_map(|key| field(key).filter(|value| !value.is_empty()))
    .ok_or_else(bad)?;
    let at = timestamp(raw)?;
    let mut entities = Vec::new();
    for (kind, key) in [
        ("host", "Computer"),
        ("user", "UserName"),
        ("process", "ExecutableName"),
        ("process", "Application"),
        ("file", "SourceFilename"),
        ("file", "FullPath"),
        ("file", "Path"),
        ("file", "FileName"),
        ("registry", "KeyPath"),
    ] {
        if let Some(value) = field(key).filter(|text| !text.is_empty() && text.len() <= 4096) {
            entities.push((kind.into(), value.into()));
        }
    }
    entities.sort();
    entities.dedup();
    Ok(GraphRecord {
        index,
        at,
        event: tool.into(),
        text: serde_json::json!({"tool":tool,"columns":headers.iter().zip(row.iter()).collect::<std::collections::BTreeMap<_,_>>()}).to_string(),
        entities,
        relations: Vec::new(),
    })
}
fn timestamp(raw: &str) -> Result<String, AppError> {
    let instant = if let Ok(value) = DateTime::parse_from_rfc3339(raw) {
        value.with_timezone(&Utc)
    } else if let Ok(value) = DateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f %:z") {
        value.with_timezone(&Utc)
    } else if let Ok(value) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f") {
        value.and_utc()
    } else {
        return Err(bad());
    };
    let at = instant.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    UtcTimestamp::parse(&at).map_err(|_| bad())?;
    Ok(at)
}
fn bad() -> AppError {
    AppError::Policy("invalid EZTools CSV row".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_tool_has_a_distinct_exact_header_signature() {
        for (tool, required) in HEADERS {
            let headers = csv::StringRecord::from(required.to_vec());
            assert_eq!(tool_for_headers(&headers), Some(*tool));
            let lowercase = csv::StringRecord::from(
                required
                    .iter()
                    .map(|field| field.to_ascii_lowercase())
                    .collect::<Vec<_>>(),
            );
            assert_eq!(tool_for_headers(&lowercase), None);
        }
    }
}
