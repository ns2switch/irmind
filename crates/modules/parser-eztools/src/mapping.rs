use irmind_app::AppError;

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
