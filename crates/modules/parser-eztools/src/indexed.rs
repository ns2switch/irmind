use irmind_app::{AppError, GraphRecord, IndexedProjection, indexed_rfc3339};
use serde::Deserialize;
fn invalid() -> AppError {
    AppError::Policy("invalid precise source timestamp".into())
}
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow)]
    columns: Columns<'a>,
}
#[derive(Deserialize)]
struct Columns<'a> {
    #[serde(borrow, rename = "RunTime")]
    f0: Option<&'a str>,
    #[serde(borrow, rename = "LastRun")]
    f1: Option<&'a str>,
    #[serde(borrow, rename = "FileKeyLastWriteTimestamp")]
    f2: Option<&'a str>,
    #[serde(borrow, rename = "LastModifiedTimeUTC")]
    f3: Option<&'a str>,
    #[serde(borrow, rename = "Created0x10")]
    f4: Option<&'a str>,
    #[serde(borrow, rename = "SourceCreated")]
    f5: Option<&'a str>,
    #[serde(borrow, rename = "LastWriteTimestamp")]
    f6: Option<&'a str>,
    #[serde(borrow, rename = "Timestamp")]
    f7: Option<&'a str>,
    #[serde(borrow, rename = "TimeCreated")]
    f8: Option<&'a str>,
}
pub(super) fn project(record: &GraphRecord) -> Result<IndexedProjection, AppError> {
    let row: Row<'_> = serde_json::from_str(&record.text).map_err(|_| invalid())?;
    let c = row.columns;
    let raw = [c.f0, c.f1, c.f2, c.f3, c.f4, c.f5, c.f6, c.f7, c.f8]
        .into_iter()
        .flatten()
        .find(|v| !v.is_empty())
        .ok_or_else(invalid)?;
    Ok((Some(indexed_rfc3339(raw, false, true)?), None))
}
