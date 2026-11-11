#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{ParseReport, ParserTimeBasis, ParserTimeContext, modules::ParserChoice};
use irmind_domain::SourceRecordV1;
use std::io::Cursor;
const MODERN: &[u8] = b"<34>1 2026-11-01T01:02:03.123456+01:00 synthetic-host sshd 321 ID47 [meta@123 a=\"literal\\]value\"] Accepted synthetic login\n";
const CLASSIC: &[u8] = b"<34>Nov  1 01:02:03 synthetic-host sshd[321]: Accepted synthetic login\n";
fn read(
    bytes: &[u8],
    context: Option<&ParserTimeContext>,
    cancel: &CancellationToken,
) -> Result<(ParseReport, Vec<SourceRecordV1>), AppError> {
    let mut rows = Vec::new();
    let report = irmind_testkit::decode_source(
        &SyslogSourceDecoder,
        "synthetic.log",
        &mut Cursor::new(bytes),
        irmind_app::sha256(bytes),
        cancel,
        context,
        &mut |row| {
            if let Some(location) = row.provenance().parser_location() {
                assert_eq!(location.parser_id(), "parser-syslog");
            } else {
                row.inspect(|record| assert!(record.origin().offset().is_none()));
            }
            row.inspect(|record| rows.push(record.clone()));
            Ok(())
        },
    )?;
    Ok((report, rows))
}
fn rows(bytes: &[u8], context: Option<&ParserTimeContext>) -> (ParseReport, Vec<SourceRecordV1>) {
    read(bytes, context, &CancellationToken::new()).unwrap()
}
#[test]
fn shares_contract_and_preserves_full_original_time() {
    irmind_testkit::run_log_parser_contract(
        &SyslogParser,
        &SyslogSourceDecoder,
        "synthetic.log",
        MODERN,
        1,
        None,
    )
    .unwrap();
    let (report, rows) = rows(MODERN, None);
    assert_eq!(report.accepted, 1);
    assert_eq!(
        rows[0].timestamp().unwrap().to_rfc3339(),
        "2026-11-01T00:02:03.123456Z"
    );
    assert_eq!(
        rows[0].fields().field("timestamp").unwrap().as_text(),
        Some("2026-11-01T01:02:03.123456+01:00")
    );
    assert_eq!(
        rows[0].fields().field("hostname").unwrap().as_text(),
        Some("synthetic-host")
    );
    assert_eq!(
        rows[0].fields().field("pri").unwrap(),
        &irmind_domain::SourceValue::Number(irmind_domain::SourceNumber::try_new("34").unwrap())
    );
    assert!(!rows[0].timestamp().unwrap().inferred());
}
#[test]
fn classic_requires_confirmed_per_ingest_context_and_records_its_basis() {
    assert!(matches!(
        read(CLASSIC, None, &CancellationToken::new()),
        Err(AppError::ParserTimeContextRequired { .. })
    ));
    for basis in [
        ParserTimeBasis::Analyst,
        ParserTimeBasis::Command,
        ParserTimeBasis::ConfirmedSuggestion,
    ] {
        let context = ParserTimeContext::new(2026, 60, true, basis).unwrap();
        let (_, output) = rows(CLASSIC, Some(&context));
        assert_eq!(
            output[0].timestamp().unwrap().to_rfc3339(),
            "2026-11-01T00:02:03Z"
        );
        assert!(output[0].timestamp().unwrap().inferred());
        assert_eq!(rows(CLASSIC, Some(&context)).1, output);
        assert_eq!(context.basis(), basis);
    }
    assert!(MANIFEST.config.is_empty());
    assert!(LegacyTimestamp::new(2026, 1440).is_err());
}
#[test]
fn malformed_record_does_not_hide_later_records_or_grow_samples() {
    let mut input = b"broken\n\xff\n<999>invalid\n".to_vec();
    input.extend_from_slice(MODERN);
    let (report, rows) = rows(&input, None);
    assert_eq!((report.rejected, report.accepted), (3, 1));
    assert_eq!(report.samples.len(), 3);
    assert_eq!(rows[0].annotations().members()[0].ordinal, 3);
    assert!(report.samples.iter().all(|sample| sample.len() <= 256));
}
#[test]
fn detector_uses_content_and_catalog_keeps_other_formats_out() {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(SyslogParser), &ModuleConfig::new())
        .unwrap();
    let catalog = registry.parser_catalog();
    assert!(matches!(
        catalog.detect("unrelated.csv", MODERN),
        ParserChoice::Auto(_)
    ));
    assert!(matches!(
        catalog.detect("syslog.log", b"{\"eventTime\":\"synthetic\"}"),
        ParserChoice::Unsupported
    ));
}
#[test]
fn cancellation_and_oversized_line_are_bounded() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        read(MODERN, None, &cancel),
        Err(AppError::Cancelled)
    ));
    let mut input = vec![b' '; 1024 * 1024 + 1];
    input.push(b'\n');
    input.extend_from_slice(MODERN);
    let (report, _) = rows(&input, None);
    assert_eq!((report.rejected, report.accepted), (1, 1));
}
fn compressed(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
#[test]
fn gzip_detects_by_content_checks_crc_and_accepts_multiple_members() {
    let first = compressed(MODERN);
    assert!(
        SyslogParser
            .detect("unrelated.bin", &first)
            .unwrap()
            .is_high()
    );
    irmind_testkit::run_log_parser_contract(
        &SyslogParser,
        &SyslogSourceDecoder,
        "compressed.bin",
        &first,
        1,
        None,
    )
    .unwrap();
    let joined = [first.clone(), compressed(MODERN)].concat();
    assert_eq!(rows(&joined, None).0.accepted, 2);
    let mut corrupt = first;
    let trailer = corrupt.len() - 8;
    corrupt[trailer] ^= 1;
    assert!(read(&corrupt, None, &CancellationToken::new()).is_err());
    let mut header = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 0];
    header.extend(std::iter::repeat_n(b'x', 65_537));
    assert!(read(&header, None, &CancellationToken::new()).is_err());
}
#[test]
fn per_ingest_context_is_typed_deterministic_and_rolls_over() {
    let context =
        ParserTimeContext::from_fields("2026", "+01:00", true, ParserTimeBasis::Command).unwrap();
    let input = b"<34>Dec 31 23:59:59 host sshd[1]: last\n<34>Jan  1 00:00:01 host sshd[1]: next\n<34>Dec 31 23:59:59 host sshd[1]: later\n<34>Nov 30 23:59:59 host sshd[1]: backward\n<34>Jan  1 00:00:01 host sshd[1]: next year\n";
    let (report, values) = rows(input, Some(&context));
    assert_eq!((report.accepted, report.rejected), (4, 1));
    assert_eq!(
        values[0].timestamp().unwrap().to_rfc3339(),
        "2026-12-31T22:59:59Z"
    );
    assert_eq!(
        values[1].timestamp().unwrap().to_rfc3339(),
        "2026-12-31T23:00:01Z"
    );
    assert_eq!(
        values[3].timestamp().unwrap().to_rfc3339(),
        "2027-12-31T23:00:01Z"
    );
    assert_eq!(rows(input, Some(&context)).1, values);
}
#[test]
fn malformed_dates_do_not_advance_the_rollover_state() {
    let context = ParserTimeContext::new(2026, 0, true, ParserTimeBasis::Analyst).unwrap();
    let input = b"<34>Dec 31 23:59:59 host sshd[1]: last\n<34>Jan 99 00:00:01 host sshd[1]: invalid\n<34>Jan  1 00:00:01 host sshd[1]: next\n";
    let (report, values) = rows(input, Some(&context));
    assert_eq!(report.rejected, 1);
    assert_eq!(
        values[1].timestamp().unwrap().to_rfc3339(),
        "2027-01-01T00:00:01Z"
    );
}
