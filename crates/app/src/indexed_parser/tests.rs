#![allow(clippy::unwrap_used)]
use super::*;
use crate::{CancellationToken, ParseReport, StreamingEventParser};
use irmind_domain::{Provenance, SourceKind};
fn row(at: &str) -> Tainted<GraphRecord> {
    Tainted::from_external(
        GraphRecord {
            index: 7,
            at: at.into(),
            event: "synthetic".into(),
            text: "{}".into(),
            entities: Vec::new(),
            relations: Vec::new(),
        },
        Provenance::new([7; 32], Some(7), SourceKind::File),
    )
}
struct Legacy;
impl StreamingEventParser for Legacy {
    fn parser_name(&self) -> &'static str {
        "parser-legacy"
    }
    fn streaming_version(&self) -> &'static str {
        "legacy-v1"
    }
    fn parse_reader(
        &self,
        _: &str,
        _: &mut dyn std::io::Read,
        _: [u8; 32],
        _: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        emit(row("1969-12-31T23:59:59.123456Z"))?;
        Ok(1)
    }
}
#[test]
fn optional_default_is_coarse_and_keeps_the_original_and_provenance() {
    let mut seen = None;
    Legacy
        .parse_indexed_reader_report(
            "a",
            &mut std::io::empty(),
            [7; 32],
            &CancellationToken::new(),
            &mut |value| {
                seen = Some(value);
                Ok(())
            },
        )
        .unwrap();
    let seen = seen.unwrap();
    assert_eq!(seen.provenance(), row("").provenance());
    seen.inspect(|value| {
        assert_eq!(value.record.at, "1969-12-31T23:59:59.123456Z");
        let time = value.time.unwrap();
        assert_eq!(time.precision(), TimePrecision::Second);
        assert_eq!(time.instant().unix_micros(), -1_000_000);
        assert_eq!(value.source_offset, None);
    });
    let missing = lift_legacy_indexed(&row("")).unwrap();
    missing.inspect(|value| assert_eq!(value.time, None));
}
#[test]
fn unsupported_precision_is_counted_and_later_records_survive() {
    let mut times = Vec::new();
    let report = parse_indexed_report(
        |emit| {
            for time in [
                "2026-11-01T00:00:00.1234567891Z",
                "2026-11-01T00:00:01.000000Z",
            ] {
                emit(row(time))?;
            }
            Ok(ParseReport {
                accepted: 2,
                rejected: 0,
                samples: Vec::new(),
            })
        },
        |r| Ok((Some(indexed_rfc3339(&r.at, false, false)?), None)),
        &mut |r| {
            r.inspect(|v| times.push(v.time));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.accepted, 1);
    assert_eq!(report.rejected, 1);
    assert_eq!(times[0].unwrap().precision(), TimePrecision::Microsecond);
    assert_eq!(report.samples.len(), 1);
}
#[test]
fn a_storage_or_cancellation_error_is_never_counted_as_a_bad_timestamp() {
    let result = parse_indexed_report(
        |emit| {
            emit(row("2026-11-01T00:00:00Z"))?;
            Ok(ParseReport {
                accepted: 1,
                rejected: 0,
                samples: Vec::new(),
            })
        },
        |r| Ok((Some(indexed_rfc3339(&r.at, false, false)?), None)),
        &mut |_| Err(AppError::Cancelled),
    );
    assert!(matches!(result, Err(AppError::Cancelled)));
}
