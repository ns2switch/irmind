use super::*;

const EVE: &[u8] = include_bytes!("../../../testkit/fixtures/parser-suricata/source/eve.jsonl");

fn records(bytes: &[u8]) -> Result<(ParseReport, Vec<GraphRecord>), AppError> {
    let mut found = Vec::new();
    let mut input = bytes;
    let report = SuricataParser.parse_reader_report(
        "eve.jsonl",
        &mut input,
        [8; 32],
        &CancellationToken::new(),
        &mut |record| {
            record.inspect(|value| found.push(value.clone()));
            Ok(())
        },
    )?;
    Ok((report, found))
}

#[test]
fn detects_eve_by_content() {
    assert_eq!(
        SuricataParser
            .detect("anything.json", EVE)
            .map(ParserConfidence::value),
        Some(95)
    );
    assert!(
        SuricataParser
            .detect("eve.json", br#"{"event_type":"alert"}"#)
            .is_none()
    );
}

#[test]
fn links_alert_and_tls_without_confirming_finding() -> Result<(), AppError> {
    let (report, rows) = records(EVE)?;
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(rows[0].event, "suricata_alert");
    assert!(rows[0].at.ends_with(".123456Z"));
    assert!(rows[0].text.contains("2026-10-23T00:00:00.123456+0000"));
    assert!(rows[0].entities.contains(&(
        "finding".into(),
        "Synthetic suspicious TLS connection".into()
    )));
    assert_eq!(rows[1].event, "suricata_tls");
    assert!(
        rows.iter()
            .all(|row| row.entities.contains(&("flow".into(), "9001001".into())))
    );
    assert!(
        rows[0]
            .relations
            .iter()
            .any(|edge| edge.relation == "triggered")
    );
    Ok(())
}

#[test]
fn all_supported_types_map_to_events() -> Result<(), AppError> {
    for kind in ["alert", "flow", "dns", "http", "tls", "fileinfo", "anomaly"] {
        let line = format!(
            "{{\"timestamp\":\"2026-10-23T00:00:00.123456+0000\",\"flow_id\":9001001,\"event_type\":\"{kind}\",\"src_ip\":\"192.0.2.1\"}}\n"
        );
        let (report, rows) = records(line.as_bytes())?;
        assert_eq!(report.accepted, 1, "{kind}");
        assert_eq!(rows[0].event, format!("suricata_{kind}"));
    }
    Ok(())
}

#[test]
fn malformed_record_does_not_hide_next_record() -> Result<(), AppError> {
    let mut input = b"{broken}\n".to_vec();
    input.extend_from_slice(EVE);
    let (report, rows) = records(&input)?;
    assert_eq!((report.accepted, report.rejected), (2, 1));
    assert_eq!(rows[0].index, 1);
    assert!(!report.samples.is_empty());
    Ok(())
}

#[test]
fn oversized_and_deep_records_do_not_hide_next_record() -> Result<(), AppError> {
    let mut input = vec![b'x'; 4 * 1024 * 1024 + 8];
    input.push(b'\n');
    input.extend_from_slice(format!("{}0{}\n", "[".repeat(65), "]".repeat(65)).as_bytes());
    input.extend_from_slice(EVE);
    let (report, rows) = records(&input)?;
    assert_eq!((report.accepted, report.rejected), (2, 2));
    assert_eq!(rows[0].index, 2);
    Ok(())
}

#[test]
fn cancellation_stops_before_consuming_input() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut input = EVE;
    let result =
        SuricataParser
            .parse_reader_report("eve.jsonl", &mut input, [8; 32], &cancel, &mut |_| Ok(()));
    assert!(matches!(result, Err(AppError::Cancelled)));
}

#[test]
fn oversized_whitespace_first_lines_are_counted_without_losing_later_records()
-> Result<(), AppError> {
    use std::io::Read as _;
    for mib in [5_u64, 50, 200] {
        let mut reader = std::io::repeat(b' ')
            .take(mib * 1024 * 1024)
            .chain(std::io::Cursor::new(b"\n"))
            .chain(std::io::Cursor::new(EVE));
        let mut indexes = Vec::new();
        let report = SuricataParser.parse_reader_report(
            "source.log",
            &mut reader,
            [6; 32],
            &CancellationToken::new(),
            &mut |record| {
                record.inspect(|row| indexes.push(row.index));
                Ok(())
            },
        )?;
        assert_eq!(report.rejected, 1);
        assert_eq!(indexes[0], 1);
        assert!(report.accepted > 0);
    }
    Ok(())
}

#[test]
#[allow(clippy::unwrap_used)]
fn indexed_events_keep_microseconds_and_request_host_partitioning() -> Result<(), AppError> {
    let parser = SuricataParser;
    assert_eq!(
        parser.source_parallelism("source.log")?,
        irmind_app::SourceParallelism::Concurrent
    );
    let mut count = 0;
    parser.parse_indexed_reader_report(
        "source.log",
        &mut std::io::Cursor::new(EVE),
        [7; 32],
        &CancellationToken::new(),
        &mut |record| {
            record.inspect(|row| {
                assert!(row.source_offset.is_some());
                let time = row.time.as_ref().unwrap();
                assert_eq!(time.precision(), irmind_app::TimePrecision::Microsecond);
                assert_ne!(time.instant().unix_micros().rem_euclid(1_000_000), 0);
                assert_eq!(
                    parser.partition_profile(&row.record),
                    irmind_app::PartitionProfile::EndpointHost
                );
                count += 1;
            });
            assert!(record.provenance().parser_location().is_some());
            Ok(())
        },
    )?;
    assert!(count > 0);
    Ok(())
}

#[test]
fn shared_streaming_contract() -> Result<(), AppError> {
    irmind_testkit::run_log_parser_contract(&SuricataParser, "source.log", EVE, 2)
}

#[test]
fn escaped_json_strings_are_valid_bounded_data() -> Result<(), AppError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(EVE.split(|b| *b == b'\n').next().unwrap_or(EVE))
            .map_err(|_| AppError::Policy("invalid fixture".into()))?;
    value["host"] = serde_json::Value::String("synthetic \"quoted\"".into());
    let bytes =
        serde_json::to_vec(&value).map_err(|_| AppError::Policy("invalid fixture".into()))?;
    let (report, rows) = records(&bytes)?;
    assert_eq!(report.accepted, 1);
    assert_eq!(report.rejected, 0);
    assert!(!rows.is_empty());
    Ok(())
}

#[test]
fn explicitly_zero_microseconds_are_not_downgraded() -> Result<(), AppError> {
    let input =
        br#"{"timestamp":"2026-10-23T00:00:00.000000+0000","flow_id":1,"event_type":"flow"}"#;
    let (_, rows) = records(input)?;
    assert!(rows[0].at.ends_with(".000000Z"));
    assert_eq!(
        irmind_app::indexed_rfc3339(&rows[0].at, false, false)?.precision(),
        irmind_app::TimePrecision::Microsecond
    );
    Ok(())
}
