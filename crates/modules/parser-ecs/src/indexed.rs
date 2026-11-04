use irmind_app::{AppError, GraphRecord, IndexedProjection, indexed_rfc3339};
pub(super) fn project(record: &GraphRecord) -> Result<IndexedProjection, AppError> {
    let value: serde_json::Value = serde_json::from_str(&record.text).map_err(|_| invalid())?;
    let raw = value
        .pointer("/attributes/@timestamp")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    Ok((Some(indexed_rfc3339(raw, false, false)?), None))
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::PolicyInvalidIndexedTimestamp)
}
