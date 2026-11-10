use irmind_app::{AppError, GraphRecord, IndexedProjection, IndexedTime, TimePrecision};
use serde::Deserialize;
#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow)]
    time: &'a str,
}
pub(super) fn project(
    parser: &crate::DeclarativeParser,
    record: &GraphRecord,
) -> Result<IndexedProjection, AppError> {
    let row: Row<'_> = serde_json::from_str(&record.text)
        .map_err(|_| AppError::Fixed(irmind_app::FixedAppError::PolicyInvalidIndexedTimestamp))?;
    Ok((Some(timestamp(parser, row.time, &record.at)?), None))
}
pub(super) fn timestamp(
    parser: &crate::DeclarativeParser,
    value: &str,
    at: &str,
) -> Result<IndexedTime, AppError> {
    let format = parser.definition.timestamp.format.as_str();
    let time = if format == "rfc3339" {
        irmind_app::indexed_rfc3339(value, false, false)?
    } else if format == "unix" {
        IndexedTime::from_epoch_decimal(value, false).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::PolicyInvalidIndexedTimestamp)
        })?
    } else {
        let inferred = !format.contains("%z")
            && !format.contains("%:z")
            && !format.contains("%#z")
            && !format.contains("%+");
        let time = irmind_app::indexed_rfc3339(at, inferred, false)?;
        let precision = if format.contains("%3f") || format.contains("%.3f") {
            TimePrecision::Millisecond
        } else if format.contains("%6f") || format.contains("%.6f") {
            TimePrecision::Microsecond
        } else if format.contains("%f")
            || format.contains("%.f")
            || format.contains("%9f")
            || format.contains("%.9f")
        {
            TimePrecision::Nanosecond
        } else {
            TimePrecision::Second
        };
        IndexedTime::new(time.instant(), precision, inferred).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::PolicyInvalidIndexedTimestamp)
        })?
    };
    Ok(time)
}
