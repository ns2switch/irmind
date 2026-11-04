use irmind_app::{AppError, GraphRecord, IndexedProjection, IndexedTime, indexed_rfc3339};
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
#[derive(Deserialize)]
struct Journal<'a> {
    #[serde(borrow, rename = "__REALTIME_TIMESTAMP")]
    micros: Option<&'a str>,
}
#[derive(Deserialize)]
struct Audit<'a> {
    #[serde(borrow)]
    event: Row<'a>,
}
fn normalized(record: &GraphRecord) -> Result<Row<'_>, AppError> {
    if matches!(record.event.as_str(), "process_execute" | "audit_event") {
        serde_json::from_str::<Audit<'_>>(&record.text)
            .map(|v| v.event)
            .map_err(|_| invalid())
    } else {
        serde_json::from_str(&record.text).map_err(|_| invalid())
    }
}
pub(super) fn project(record: &GraphRecord) -> Result<IndexedProjection, AppError> {
    let row = normalized(record)?;
    let time = if row.raw.trim_start().starts_with('{') {
        let raw: Journal<'_> = serde_json::from_str(row.raw.as_ref()).map_err(|_| invalid())?;
        if let Some(micros) = raw.micros {
            IndexedTime::new(
                irmind_app::IndexedInstant::new(micros.parse().map_err(|_| invalid())?, 0)
                    .map_err(|_| invalid())?,
                irmind_app::TimePrecision::Microsecond,
                false,
            )
            .map_err(|_| invalid())?
        } else {
            indexed_rfc3339(row.timestamp, row.timestamp_inferred, false)?
        }
    } else if let Some(rest) = row.raw.split_once("msg=audit(").map(|(_, v)| v) {
        IndexedTime::from_epoch_decimal(rest.split_once(':').ok_or_else(invalid)?.0, false)
            .map_err(|_| invalid())?
    } else {
        indexed_rfc3339(row.timestamp, row.timestamp_inferred, false)?
    };
    Ok((Some(time), None))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::{CancellationToken, StreamingEventParser};
    #[test]
    fn audit_source_retains_exact_decimal_time() {
        let bytes = include_bytes!("../../../testkit/fixtures/parser-linux/source/audit.log");
        crate::LinuxParser::default()
            .parse_reader_report(
                "audit.log",
                &mut std::io::Cursor::new(bytes),
                [0; 32],
                &CancellationToken::new(),
                &mut |r| {
                    r.inspect(|record| {
                        let row = normalized(record).unwrap();
                        let raw = row
                            .raw
                            .split_once("msg=audit(")
                            .unwrap()
                            .1
                            .split_once(':')
                            .unwrap()
                            .0;
                        assert!(IndexedTime::from_epoch_decimal(raw, false).is_ok(), "{raw}");
                        assert!(project(record).is_ok());
                    });
                    Ok(())
                },
            )
            .unwrap();
    }
    #[test]
    fn journal_source_round_trips_its_escaped_raw_record() {
        let bytes = include_bytes!("../../../testkit/fixtures/parser-linux/source/journal.jsonl");
        crate::LinuxParser::default()
            .parse_reader_report(
                "journal.jsonl",
                &mut std::io::Cursor::new(bytes),
                [0; 32],
                &CancellationToken::new(),
                &mut |r| {
                    r.inspect(|record| {
                        let row = normalized(record).unwrap();
                        let raw: Journal<'_> = serde_json::from_str(row.raw.as_ref()).unwrap();
                        assert!(raw.micros.is_some());
                        assert!(project(record).is_ok());
                    });
                    Ok(())
                },
            )
            .unwrap();
    }
}
