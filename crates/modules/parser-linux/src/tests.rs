#![allow(clippy::unwrap_used)]
use super::*;
const AUTH: &[u8] = b"Nov  1 01:00:00 synthetic-linux sshd[1]: Accepted password for synthetic-user from 203.0.113.77 port 4242 ssh2\n";
const JOURNAL: &[u8] = br#"{"__REALTIME_TIMESTAMP":"1793494800123456","_HOSTNAME":"synthetic-linux","_PID":"42","_UID":"1000","_CMDLINE":"sh -c \"synthetic\"","MESSAGE":"synthetic journal entry"}
"#;
const WEB: &[u8] = b"203.0.113.77 - synthetic-user [01/Nov/2026:01:00:00 +0000] \"GET /synthetic HTTP/1.1\" 200 12\n";
fn configured() -> LinuxParser {
    LinuxParser::configured(
        ParserTimeContext::new(2026, 0, true, irmind_app::ParserTimeBasis::Analyst).unwrap(),
    )
}
fn rows(parser: &LinuxParser, bytes: &[u8]) -> (ParseReport, Vec<GraphRecord>) {
    let mut rows = vec![];
    let report = parser
        .parse_reader_report(
            "synthetic.log",
            &mut &bytes[..],
            [1; 32],
            &CancellationToken::new(),
            &mut |row| {
                row.inspect(|record| rows.push(record.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, rows)
}
#[test]
fn shared_contract_for_auth_journal_and_http() {
    for bytes in [AUTH, JOURNAL, WEB] {
        let parser = configured();
        irmind_testkit::run_log_parser_contract(&parser, "synthetic.log", bytes, 1).unwrap();
    }
}
#[test]
fn journal_retains_microseconds_and_borrowed_or_escaped_fields() {
    let (report, rows) = rows(&LinuxParser::default(), JOURNAL);
    assert_eq!(report.accepted, 1);
    assert!(rows[0].text.contains("1793494800123456"));
    assert!(rows[0].text.contains(".123456Z"));
    assert!(
        rows[0]
            .entities
            .iter()
            .any(|(kind, value)| kind == "command_line" && value == "sh -c \"synthetic\"")
    );
}
#[test]
fn auth_requires_context_and_rollover_is_local_to_each_stream() {
    assert!(matches!(
        LinuxParser::default().parse_reader_report(
            "auth.log",
            &mut &AUTH[..],
            [1; 32],
            &CancellationToken::new(),
            &mut |_| Ok(())
        ),
        Err(AppError::ParserTimeContextRequired { .. })
    ));
    let bytes = b"Dec 31 23:59:59 synthetic-linux sshd[1]: first\nJan  1 00:00:00 synthetic-linux sshd[1]: next\nNov 30 23:59:59 synthetic-linux sshd[1]: later\nOct 30 23:59:59 synthetic-linux sshd[1]: invalid\n";
    let parser = configured();
    let (report, output) = rows(&parser, bytes);
    assert_eq!((report.accepted, report.rejected), (3, 1));
    assert_eq!(output[1].at, "2027-01-01T00:00:00Z");
    assert_eq!(rows(&parser, bytes).1, output);
    let restored = LinuxParser::from_version(parser.identity().version).unwrap();
    assert_eq!(rows(&restored, bytes).1, output);
}
#[test]
fn audit_groups_serials_and_marks_unterminated_events_partial() {
    let bytes = b"node=synthetic-linux type=SYSCALL msg=audit(1793494800.123456:1): syscall=59 uid=1000 auid=1000 pid=42 exe=\"/bin/sh\" success=yes\nnode=synthetic-linux type=EXECVE msg=audit(1793494800.123456:1): argc=2 a0=\"sh\" a1=\"synthetic\"\nnode=synthetic-linux type=EOE msg=audit(1793494800.123456:1):\nnode=synthetic-linux type=SYSCALL msg=audit(1793494801.123456:2): syscall=2 uid=1000 auid=1000 pid=43\n";
    let (report, records) = rows(&LinuxParser::default(), bytes);
    assert_eq!(report.accepted, 2);
    assert_eq!(records[0].event, "process_execute");
    assert!(records[0].text.contains("\"partial\":false"));
    assert!(records[1].text.contains("\"partial\":true"));
    assert!(records[0].text.contains(".123456Z"));
    assert_eq!((records[0].index, records[1].index), (0, 3));
}

#[test]
fn complete_fixture_maps_sockaddr_and_keeps_component_offsets() {
    let input = include_bytes!("../../../testkit/fixtures/parser-linux/source/audit.log");
    let (report, output) = rows(&LinuxParser::default(), input);
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert!(
        output[0]
            .entities
            .iter()
            .any(|(kind, value)| kind == "ip" && value == "203.0.113.77")
    );
    let record: serde_json::Value = serde_json::from_str(&output[0].text).unwrap();
    assert_eq!(record["event"]["socket_port"], "80");
    assert!(record["event"]["source_ip"].is_null());
    assert_eq!(record["record_locations"].as_array().unwrap().len(), 6);
    assert_eq!(record["arguments"], serde_json::json!(["sh", "synthetic"]));
}
#[test]
fn execve_reassembles_chunks_without_decoding_quoted_hex_literals() {
    let input = b"type=SYSCALL msg=audit(1793494800.1:1): uid=1000 syscall=59\ntype=EXECVE msg=audit(1793494800.1:1): argc=2 a0=2f62696e2f7368 a1_len=8 a1[0]=\"6361\"\ntype=EXECVE msg=audit(1793494800.1:1): a1[1]=\"7421\"\ntype=EOE msg=audit(1793494800.1:1):\n";
    let (_, records) = rows(&LinuxParser::default(), input);
    let record: serde_json::Value = serde_json::from_str(&records[0].text).unwrap();
    assert_eq!(
        record["arguments"],
        serde_json::json!(["/bin/sh", "63617421"])
    );
    assert_eq!(record["arguments_complete"], true);
    assert_eq!(record["event"]["partial"], false);
}
#[test]
fn malformed_record_and_bounded_samples_do_not_hide_later_valid_records() {
    let mut input = b"invalid\n{broken}\n".to_vec();
    input.extend_from_slice(WEB);
    let (report, records) = rows(&LinuxParser::default(), &input);
    assert_eq!((report.accepted, report.rejected), (1, 2));
    assert_eq!(records[0].index, 2);
    assert!(report.samples.iter().all(|sample| sample.len() <= 256));
    let mut huge = vec![b'x'; 1024 * 1024 + 1];
    huge.push(b'\n');
    huge.extend_from_slice(WEB);
    assert_eq!(rows(&LinuxParser::default(), &huge).0.accepted, 1);
}
#[test]
fn partial_audit_timeout_limits_and_orphan_eoe_are_visible() {
    let mut input = b"type=SYSCALL msg=audit(1793494800.1:1): uid=1000\ntype=SYSCALL msg=audit(1793494803.1:2): uid=1000\ntype=EOE msg=audit(1793494804.1:3):\n".to_vec();
    let (_, events) = rows(&LinuxParser::default(), &input);
    assert_eq!(events.len(), 3);
    assert!(
        events
            .iter()
            .all(|event| event.text.contains("\"partial\":true"))
    );
    input.clear();
    for _ in 0..130 {
        input.extend_from_slice(b"type=SYSCALL msg=audit(1793494800.1:1): uid=1000\n");
    }
    input.extend_from_slice(WEB);
    let (report, events) = rows(&LinuxParser::default(), &input);
    assert_eq!(report.rejected, 2);
    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|event| event.event == "http_access"));
}
#[test]
fn cancellation_and_depth_or_field_limits_fail_closed() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        LinuxParser::default().parse_reader_report(
            "synthetic",
            &mut &WEB[..],
            [1; 32],
            &cancel,
            &mut |_| Ok(())
        ),
        Err(AppError::Cancelled)
    ));
    assert!(!super::bounds::json_shape(
        format!("{}0{}", "[".repeat(65), "]".repeat(65)).as_bytes()
    ));
    let huge = format!(
        "{{{}}}",
        (0..1025)
            .map(|index| format!("\"key{index}\":0"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(!super::bounds::json_shape(huge.as_bytes()));
}
#[test]
fn generic_syslog_with_pri_stays_with_its_existing_module() {
    assert!(
        LinuxParser::default()
            .detect(
                "synthetic",
                b"<34>Nov  1 01:00:00 host sshd[1]: Accepted password"
            )
            .is_none()
    );
}
