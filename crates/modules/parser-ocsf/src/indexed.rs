use irmind_app::{
    AppError, GraphRecord, IndexedInstant, IndexedProjection, IndexedTime, TimePrecision,
    indexed_rfc3339,
};
pub(super) fn project(record: &GraphRecord) -> Result<IndexedProjection, AppError> {
    let value: serde_json::Value = serde_json::from_str(&record.text).map_err(|_| invalid())?;
    let time = if let Some(raw) = value
        .pointer("/attributes/time_dt")
        .and_then(serde_json::Value::as_str)
    {
        indexed_rfc3339(raw, false, false)?
    } else {
        let micros = value
            .pointer("/attributes/time")
            .and_then(serde_json::Value::as_i64)
            .and_then(|v| v.checked_mul(1000))
            .ok_or_else(invalid)?;
        IndexedTime::new(
            IndexedInstant::new(micros, 0).map_err(|_| invalid())?,
            TimePrecision::Millisecond,
            false,
        )
        .map_err(|_| invalid())?
    };
    Ok((Some(time), None))
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::PolicyInvalidIndexedTimestamp)
}
