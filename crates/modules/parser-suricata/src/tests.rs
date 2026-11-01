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
