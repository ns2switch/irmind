use irmind_app::{AppError, GraphRecord, IndexedProjection, IndexedTime, indexed_rfc3339};
use serde::Deserialize;
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::PolicyInvalidIndexedTimestamp)
}
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow)]
    datetime: Option<&'a str>,
    timestamp: Option<i64>,
}
pub(super) fn project(record: &GraphRecord) -> Result<IndexedProjection, AppError> {
    let row: Row<'_> = serde_json::from_str(&record.text).map_err(|_| invalid())?;
    let time = if let Some(micros) = row.timestamp {
        let instant = irmind_app::IndexedInstant::new(micros, 0).map_err(|_| invalid())?;
        if let Some(raw) = row.datetime {
            let declared = indexed_rfc3339(raw, false, false)?;
            let unit = match declared.precision() {
                irmind_app::TimePrecision::Second => 1_000_000,
                irmind_app::TimePrecision::Millisecond => 1000,
                _ => 1,
            };
            if instant.unix_micros().div_euclid(unit)
                != declared.instant().unix_micros().div_euclid(unit)
            {
                return Err(invalid());
            }
            if declared.precision() == irmind_app::TimePrecision::Nanosecond {
                return Ok((Some(declared), None));
            }
        }
        IndexedTime::new(instant, irmind_app::TimePrecision::Microsecond, false)
            .map_err(|_| invalid())?
    } else {
        indexed_rfc3339(row.datetime.ok_or_else(invalid)?, false, false)?
    };
    Ok((Some(time), None))
}
