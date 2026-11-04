use irmind_app::{AppError, GraphRecord, IndexedProjection, indexed_rfc3339};
use serde::Deserialize;
fn invalid() -> AppError {
    AppError::Policy("invalid precise source timestamp".into())
}
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, rename = "Timestamp", alias = "timestamp", alias = "Time")]
    at: &'a str,
}
pub(super) fn project(record: &GraphRecord) -> Result<IndexedProjection, AppError> {
    let row: Row<'_> = serde_json::from_str(&record.text).map_err(|_| invalid())?;
    Ok((Some(indexed_rfc3339(row.at, false, false)?), None))
}
