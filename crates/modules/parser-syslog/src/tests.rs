#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::modules::ParserChoice;
use std::io::Cursor;

const MODERN: &[u8] = b"<34>1 2026-11-01T01:02:03.123456+01:00 synthetic-host sshd 321 ID47 [meta@123 a=\"literal\\]value\"] Accepted synthetic login\n";
const CLASSIC: &[u8] = b"<34>Nov  1 01:02:03 synthetic-host sshd[321]: Accepted synthetic login\n";

fn rows(parser: &SyslogParser, bytes: &[u8]) -> (ParseReport, Vec<GraphRecord>) {
    let mut rows = Vec::new();
    let report = parser
        .parse_reader_report(
            "synthetic.log",
            &mut Cursor::new(bytes),
            irmind_app::sha256(bytes),
            &CancellationToken::new(),
            &mut |row| {
                assert_eq!(
                    row.provenance().parser_location().unwrap().parser_id(),
                    "parser-syslog"
                );
                row.inspect(|record| rows.push(record.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, rows)
}

#[test]
fn shares_contract_and_preserves_full_original_time() {
    let parser = SyslogParser::default();
    irmind_testkit::run_log_parser_contract(&parser, "synthetic.log", MODERN, 1).unwrap();
    let (report, rows) = rows(&parser, MODERN);
    assert_eq!(report.accepted, 1);
    assert_eq!(rows[0].at, "2026-11-01T00:02:03Z");
    let value: serde_json::Value = serde_json::from_str(&rows[0].text).unwrap();
    assert_eq!(value["timestamp"], "2026-11-01T00:02:03.123456Z");
    assert!(value["raw"].as_str().unwrap().contains("03.123456+01:00"));
    assert_eq!(value["facility"], 4);
    assert_eq!(value["severity"], 2);
    assert_eq!(value["timestamp_inferred"], false);
}

#[test]
fn classic_requires_context_and_records_its_basis() {
    let (report, _) = rows(&SyslogParser::from_version("syslog-v1").unwrap(), CLASSIC);
    assert_eq!(report.rejected, 1);
    let parser = SyslogParser::new(Some(LegacyTimestamp::new(2026, 60).unwrap()));
    let (_, rows) = rows(&parser, CLASSIC);
    assert_eq!(rows[0].at, "2026-11-01T00:02:03Z");
    assert!(rows[0].text.contains("\"timestamp_inferred\":true"));
    assert!(
        parser
            .timestamp_context()
            .unwrap()
            .contains("year=2026;offset_minutes=60;basis=analyst")
    );
    let restored = SyslogParser::from_version(parser.identity().version).unwrap();
    assert_eq!(restored.identity().version, parser.identity().version);
    assert_eq!(restored.timestamp_context(), parser.timestamp_context());
}

#[test]
fn malformed_record_does_not_hide_later_records_or_grow_samples() {
    let mut input = b"broken\n\xff\n<999>invalid\n".to_vec();
    input.extend_from_slice(MODERN);
    let (report, rows) = rows(&SyslogParser::default(), &input);
    assert_eq!(report.rejected, 3);
    assert_eq!(report.samples.len(), 3);
    assert_eq!(report.accepted, 1);
    assert_eq!(rows[0].index, 3);
    assert!(report.samples.iter().all(|sample| sample.len() <= 256));
}

#[test]
fn detector_uses_content_and_catalog_keeps_other_formats_out() {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(SyslogParser::default()), &ModuleConfig::new())
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
    assert!(LegacyTimestamp::new(2026, 1440).is_err());
    assert!(SyslogParser::from_version("syslog-v1:year=02026;offset=0").is_err());
}

#[test]
fn cancellation_and_oversized_line_are_bounded() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        SyslogParser::default().parse_reader(
            "synthetic.log",
            &mut Cursor::new(MODERN),
            [0; 32],
            &cancel,
            &mut |_| Err(AppError::Policy("cancelled parser emitted".into()))
        ),
        Err(AppError::Cancelled)
    ));
    let mut input = vec![b' '; 1024 * 1024 + 1];
    input.push(b'\n');
    input.extend_from_slice(MODERN);
    let (report, _) = rows(&SyslogParser::default(), &input);
    assert_eq!(report.rejected, 1);
    assert_eq!(report.accepted, 1);
}

fn compressed(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn gzip_detects_by_content_checks_crc_and_accepts_multiple_members() {
    let parser = SyslogParser::default();
    let first = compressed(MODERN);
    assert!(parser.detect("unrelated.bin", &first).unwrap().is_high());
    irmind_testkit::run_log_parser_contract(&parser, "compressed.bin", &first, 1).unwrap();
    let joined = [first.clone(), compressed(MODERN)].concat();
    assert_eq!(rows(&parser, &joined).0.accepted, 2);
    let mut corrupt = first;
    let trailer = corrupt.len() - 8;
    corrupt[trailer] ^= 1;
    assert!(
        parser
            .parse_reader(
                "corrupt.gz",
                &mut corrupt.as_slice(),
                [0; 32],
                &CancellationToken::new(),
                &mut |_| Ok(())
            )
            .is_err()
    );
    let mut header = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 0];
    header.extend(std::iter::repeat_n(b'x', 65_537));
    assert!(
        parser
            .parse_reader(
                "header.gz",
                &mut header.as_slice(),
                [0; 32],
                &CancellationToken::new(),
                &mut |_| Ok(())
            )
            .is_err()
    );
}

#[test]
fn per_ingest_context_is_typed_signed_versioned_and_rolls_over() {
    use irmind_app::{ParserTimeBasis, ParserTimeContext};
    let context =
        ParserTimeContext::from_fields("2026", "+01:00", true, ParserTimeBasis::Command).unwrap();
    let parser = SyslogParser::configured(context).unwrap();
    let input = b"<34>Dec 31 23:59:59 host sshd[1]: last\n<34>Jan  1 00:00:01 host sshd[1]: next\n<34>Dec 31 23:59:59 host sshd[1]: later\n<34>Nov 30 23:59:59 host sshd[1]: backward\n<34>Jan  1 00:00:01 host sshd[1]: next year\n";
    let (report, values) = rows(&parser, input);
    assert_eq!((report.accepted, report.rejected), (4, 1));
    assert_eq!(values[0].at, "2026-12-31T22:59:59Z");
    assert_eq!(values[1].at, "2026-12-31T23:00:01Z");
    assert_eq!(values[3].at, "2027-12-31T23:00:01Z");
    assert!(
        parser
            .timestamp_context()
            .unwrap()
            .contains("basis=command")
    );
    let restored = SyslogParser::from_version(parser.identity().version).unwrap();
    assert_eq!(rows(&restored, input).1, values);
    assert!(
        SyslogParser::default()
            .parse_reader(
                "source.log",
                &mut Cursor::new(CLASSIC),
                [0; 32],
                &CancellationToken::new(),
                &mut |_| Ok(())
            )
            .is_err()
    );
}

#[test]
fn malformed_dates_do_not_advance_the_rollover_state() {
    use irmind_app::{ParserTimeBasis, ParserTimeContext};
    let parser = SyslogParser::configured(
        ParserTimeContext::new(2026, 0, true, ParserTimeBasis::Analyst).unwrap(),
    )
    .unwrap();
    let input = b"<34>Dec 31 23:59:59 host sshd[1]: last\n<34>Jan 99 00:00:01 host sshd[1]: invalid\n<34>Jan  1 00:00:01 host sshd[1]: next\n";
    let (report, values) = rows(&parser, input);
    assert_eq!(report.rejected, 1);
    assert_eq!(values[1].at, "2027-01-01T00:00:01Z");
}

#[test]
fn versions_are_canonical_and_source_time_context_requires_no_global_settings() {
    use irmind_app::{ParserTimeBasis, ParserTimeContext};
    assert!(MANIFEST.config.is_empty());
    for basis in [
        ParserTimeBasis::Analyst,
        ParserTimeBasis::Command,
        ParserTimeBasis::ConfirmedSuggestion,
    ] {
        let configured =
            SyslogParser::configured(ParserTimeContext::new(2026, -210, false, basis).unwrap())
                .unwrap();
        let restored = SyslogParser::from_version(configured.identity().version).unwrap();
        assert_eq!(restored.timestamp_context(), configured.timestamp_context());
        assert_eq!(rows(&restored, CLASSIC).1, rows(&configured, CLASSIC).1);
    }
    for version in [
        "syslog-v2:year=02026;offset=0;rollover=1;basis=analyst",
        "syslog-v2:year=2026;offset=0;rollover=true;basis=analyst",
        "syslog-v2:year=2026;offset=0;rollover=1;basis=untrusted",
        "syslog-v2:year=2026;offset=0;rollover=1;basis=analyst;extra=1",
    ] {
        assert!(SyslogParser::from_version(version).is_err());
    }
}
