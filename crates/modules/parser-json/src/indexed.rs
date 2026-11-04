use irmind_app::{AppError, GraphRecord, IndexedProjection, indexed_rfc3339};
pub(super) fn project(record: &GraphRecord) -> Result<IndexedProjection, AppError> {
    Ok((
        if record.at.is_empty() {
            None
        } else {
            Some(indexed_rfc3339(&record.at, false, false)?)
        },
        None,
    ))
}
