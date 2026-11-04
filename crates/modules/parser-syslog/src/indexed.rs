use irmind_app::{AppError, GraphRecord, IndexedProjection, indexed_rfc3339};
use serde::Deserialize;
fn invalid() -> AppError {
    AppError::Policy("invalid precise source timestamp".into())
}
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow)]
    timestamp: &'a str,
    timestamp_inferred: bool,
    #[serde(borrow)]
    raw: std::borrow::Cow<'a, str>,
}
pub(super) fn project(record: &GraphRecord) -> Result<IndexedProjection, AppError> {
    let row: Row<'_> = serde_json::from_str(&record.text).map_err(|_| invalid())?;
    if row.timestamp.is_empty() {
        return Ok((None, None));
    }
    let raw = if row.timestamp_inferred {
        row.timestamp
    } else {
        row.raw
            .split_once(">1 ")
            .and_then(|(_, v)| v.split(' ').next())
            .ok_or_else(invalid)?
    };
    Ok((
        Some(indexed_rfc3339(raw, row.timestamp_inferred, false)?),
        None,
    ))
}
