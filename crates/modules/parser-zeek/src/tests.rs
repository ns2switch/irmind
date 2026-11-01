use super::*;

const TSV: &[u8] = include_bytes!("../../../testkit/fixtures/parser-zeek/source/events.log");
const JSON: &[u8] = include_bytes!("../../../testkit/fixtures/parser-zeek/source/dns.jsonl");

fn records(source: &str, bytes: &[u8]) -> Result<(ParseReport, Vec<GraphRecord>), AppError> {
    let mut found = Vec::new();
    let mut input = bytes;
    let report = ZeekParser.parse_reader_report(
        source,
        &mut input,
        [7; 32],
        &CancellationToken::new(),
        &mut |record| {
            record.inspect(|value| found.push(value.clone()));
            Ok(())
        },
    )?;
    Ok((report, found))
}

#[test]
fn detects_tsv_and_json_by_content() {
    assert_eq!(
        ZeekParser
            .detect("anything.log", TSV)
            .map(ParserConfidence::value),
        Some(95)
    );
    assert_eq!(
        ZeekParser
            .detect("anything.json", JSON)
            .map(ParserConfidence::value),
        Some(95)
    );
    assert!(
        ZeekParser
            .detect("conn.log", br#"{"event_type":"flow"}"#)
            .is_none()
    );
}

#[test]
fn tsv_and_json_keep_full_timestamp_and_uid() -> Result<(), AppError> {
    let (report, rows) = records("events.log", TSV)?;
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(rows[0].event, "zeek_conn");
    assert!(rows[0].at.ends_with(".123456Z"));
    assert!(rows[0].text.contains("1790000000.123456"));
    assert!(
        rows[0]
            .entities
            .contains(&("uid".into(), "CsyntheticZeek1".into()))
    );
    let (report, dns) = records("dns.jsonl", JSON)?;
    assert_eq!(report.accepted, 1);
    assert_eq!(dns[0].event, "zeek_dns");
    assert!(dns[0].at.ends_with(".123458Z"));
    assert!(
        dns[0]
            .entities
            .contains(&("uid".into(), "CsyntheticZeek1".into()))
    );
    assert!(
        dns[0]
            .entities
            .contains(&("domain".into(), "synthetic.example.test".into()))
    );
    Ok(())
}

#[test]
fn malformed_row_does_not_hide_next_record() -> Result<(), AppError> {
    let mut input = TSV.to_vec();
    input.extend_from_slice(b"bad\trow\n");
    input.extend_from_slice(
        b"1790000000.123459\tCnext\t192.0.2.15\t1111\t198.51.100.23\t443\ttcp\tssl\n",
    );
    let (report, rows) = records("events.log", &input)?;
    assert_eq!((report.accepted, report.rejected), (3, 1));
    assert_eq!(rows[2].index, 3);
    assert!(!report.samples.is_empty());
    Ok(())
}

#[test]
fn oversized_row_is_bounded_and_next_row_survives() -> Result<(), AppError> {
    let mut input = TSV.to_vec();
    input.extend(std::iter::repeat_n(b'x', 4 * 1024 * 1024 + 8));
    input.push(b'\n');
    input.extend_from_slice(
        b"1790000000.123459\tCnext\t192.0.2.15\t1111\t198.51.100.23\t443\ttcp\tssl\n",
    );
    let (report, rows) = records("events.log", &input)?;
    assert_eq!((report.accepted, report.rejected), (3, 1));
    assert_eq!(rows[2].index, 3);
    Ok(())
}

#[test]
fn known_json_logs_map_to_one_event_each() -> Result<(), AppError> {
    for (kind, field) in [
        ("conn", "\"service\":\"ssl\""),
        ("dns", "\"query\":\"synthetic.example.test\""),
        ("http", "\"method\":\"GET\""),
        ("ssl", "\"server_name\":\"synthetic.example.test\""),
        ("files", "\"fuid\":\"Fsynthetic\""),
        ("x509", "\"fingerprint\":\"synthetic-fingerprint\""),
        ("notice", "\"note\":\"Synthetic::Notice\""),
        ("weird", "\"name\":\"synthetic_weird\""),
    ] {
        let line = format!(
            "{{\"ts\":1790000000.123456,\"uid\":\"Csynthetic\",\"id.orig_h\":\"192.0.2.1\",{field}}}\n"
        );
        let (report, rows) = records(&format!("{kind}.log"), line.as_bytes())?;
        assert_eq!(report.accepted, 1, "{kind}");
        assert_eq!(rows[0].event, format!("zeek_{kind}"));
    }
    Ok(())
}

#[test]
fn cancellation_stops_before_consuming_input() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut input = TSV;
    let result =
        ZeekParser.parse_reader_report("events.log", &mut input, [7; 32], &cancel, &mut |_| Ok(()));
    assert!(matches!(result, Err(AppError::Cancelled)));
}
