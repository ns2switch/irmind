#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{ParseReport, ParserTimeBasis};
use irmind_domain::{SourceRecordV1, SourceValue};
const AUTH: &[u8] = b"Nov  1 01:00:00 synthetic-linux sshd[1]: Accepted password for synthetic-user from 203.0.113.77 port 4242 ssh2\n";
const JOURNAL: &[u8] = br#"{"__REALTIME_TIMESTAMP":"1793494800123456","_HOSTNAME":"synthetic-linux","_PID":"42","_UID":"1000","_CMDLINE":"sh -c \"synthetic\"","MESSAGE":"synthetic journal entry"}
"#;
const WEB: &[u8] = b"203.0.113.77 - synthetic-user [01/Nov/2026:01:00:00 +0000] \"GET /synthetic HTTP/1.1\" 200 12\n";
fn context() -> ParserTimeContext {
    ParserTimeContext::new(2026, 0, true, ParserTimeBasis::Analyst).unwrap()
}
fn read(
    bytes: &[u8],
    context: Option<&ParserTimeContext>,
    cancel: &CancellationToken,
) -> Result<(ParseReport, Vec<SourceRecordV1>), AppError> {
    let mut rows = vec![];
    let report = irmind_testkit::decode_source(
        &LinuxSourceDecoder,
        "synthetic.log",
        &mut &bytes[..],
        irmind_app::sha256(bytes),
        cancel,
        context,
        &mut |row| {
            row.inspect(|record| rows.push(record.clone()));
            Ok(())
        },
    )?;
    Ok((report, rows))
}
fn rows(bytes: &[u8], context: Option<&ParserTimeContext>) -> (ParseReport, Vec<SourceRecordV1>) {
    read(bytes, context, &CancellationToken::new()).unwrap()
}
fn members(record: &SourceRecordV1) -> &[SourceValue] {
    match record.fields().field("records").unwrap() {
        SourceValue::Array(records) => Some(records.as_slice()),
        _ => None,
    }
    .unwrap()
}
#[test]
fn shared_contract_for_auth_journal_and_http() {
    for bytes in [AUTH, JOURNAL, WEB] {
        irmind_testkit::run_log_parser_contract(
            &LinuxParser,
            &LinuxSourceDecoder,
            "synthetic.log",
            bytes,
            1,
            Some(&context()),
        )
        .unwrap();
    }
}
#[test]
fn journal_retains_microseconds_and_borrowed_or_escaped_fields() {
    let (report, rows) = rows(JOURNAL, None);
    assert_eq!(report.accepted, 1);
    assert_eq!(
        rows[0].timestamp().unwrap().instant().unix_micros(),
        1_793_494_800_123_456
    );
    assert_eq!(
        rows[0]
            .fields()
            .field("__REALTIME_TIMESTAMP")
            .unwrap()
            .as_text(),
        Some("1793494800123456")
    );
    assert_eq!(
        rows[0].fields().field("_CMDLINE").unwrap().as_text(),
        Some("sh -c \"synthetic\"")
    );
}
#[test]
fn auth_requires_context_and_rollover_is_local_to_each_stream() {
    assert!(matches!(
        read(AUTH, None, &CancellationToken::new()),
        Err(AppError::ParserTimeContextRequired { .. })
    ));
    let bytes = b"Dec 31 23:59:59 synthetic-linux sshd[1]: first\nJan  1 00:00:00 synthetic-linux sshd[1]: next\nNov 30 23:59:59 synthetic-linux sshd[1]: later\nOct 30 23:59:59 synthetic-linux sshd[1]: invalid\n";
    let (report, output) = rows(bytes, Some(&context()));
    assert_eq!((report.accepted, report.rejected), (3, 1));
    assert_eq!(
        output[1].timestamp().unwrap().to_rfc3339(),
        "2027-01-01T00:00:00Z"
    );
    assert_eq!(rows(bytes, Some(&context())).1, output);
}
#[test]
fn audit_groups_serials_and_marks_unterminated_events_partial() {
    let bytes = b"node=synthetic-linux type=SYSCALL msg=audit(1793494800.123456:1): syscall=59 uid=1000 auid=1000 pid=42 exe=\"/bin/sh\" success=yes\nnode=synthetic-linux type=EXECVE msg=audit(1793494800.123456:1): argc=2 a0=\"sh\" a1=\"synthetic\"\nnode=synthetic-linux type=EOE msg=audit(1793494800.123456:1):\nnode=synthetic-linux type=SYSCALL msg=audit(1793494801.123456:2): syscall=2 uid=1000 auid=1000 pid=43\n";
    let (report, records) = rows(bytes, None);
    assert_eq!(report.accepted, 2);
    assert_eq!(
        members(&records[0])[0].field("syscall").unwrap().as_text(),
        Some("59")
    );
    assert!(!records[0].annotations().partial());
    assert!(records[1].annotations().partial());
    assert_eq!(
        records[0].timestamp().unwrap().instant().unix_micros(),
        1_793_494_800_123_456
    );
    assert_eq!(
        (records[0].origin().record(), records[1].origin().record()),
        (0, 1)
    );
    assert_eq!(records[1].annotations().members()[0].ordinal, 3);
}
#[test]
fn complete_fixture_keeps_sockaddr_and_all_component_offsets() {
    let input = include_bytes!("../../../testkit/fixtures/parser-linux/source/audit.log");
    let (report, output) = rows(input, None);
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(output[0].annotations().members().len(), 6);
    assert!(
        members(&output[0])
            .iter()
            .any(|v| v.field("saddr").is_some())
    );
    assert!(
        output[0]
            .annotations()
            .members()
            .windows(2)
            .all(|pair| pair[0].offset < pair[1].offset)
    );
}
#[test]
fn execve_preserves_chunks_and_decodes_only_unquoted_hex() {
    let input = b"type=SYSCALL msg=audit(1793494800.1:1): uid=1000 syscall=59\ntype=EXECVE msg=audit(1793494800.1:1): argc=2 a0=2f62696e2f7368 a1_len=8 a1[0]=\"6361\"\ntype=EXECVE msg=audit(1793494800.1:1): a1[1]=\"7421\"\ntype=EOE msg=audit(1793494800.1:1):\n";
    let (_, records) = rows(input, None);
    let parts = members(&records[0]);
    assert_eq!(parts[1].field("a0").unwrap().as_text(), Some("/bin/sh"));
    assert_eq!(parts[1].field("a1[0]").unwrap().as_text(), Some("6361"));
    assert_eq!(parts[2].field("a1[1]").unwrap().as_text(), Some("7421"));
    assert!(!records[0].annotations().partial());
}
#[test]
fn malformed_record_and_bounded_samples_do_not_hide_later_valid_records() {
    let mut input = b"invalid\n{broken}\n".to_vec();
    input.extend_from_slice(WEB);
    let (report, records) = rows(&input, None);
    assert_eq!((report.accepted, report.rejected), (1, 2));
    assert_eq!(records[0].annotations().members()[0].ordinal, 2);
    assert!(report.samples.iter().all(|sample| sample.len() <= 256));
    let mut huge = vec![b'x'; 1024 * 1024 + 1];
    huge.push(b'\n');
    huge.extend_from_slice(WEB);
    assert_eq!(rows(&huge, None).0.accepted, 1);
}
#[test]
fn partial_audit_timeout_limits_and_orphan_eoe_are_visible() {
    let mut input = b"type=SYSCALL msg=audit(1793494800.1:1): uid=1000\ntype=SYSCALL msg=audit(1793494803.1:2): uid=1000\ntype=EOE msg=audit(1793494804.1:3):\n".to_vec();
    let (_, events) = rows(&input, None);
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|event| event.annotations().partial()));
    input.clear();
    for _ in 0..130 {
        input.extend_from_slice(b"type=SYSCALL msg=audit(1793494800.1:1): uid=1000\n");
    }
    input.extend_from_slice(
        b"type=SYSCALL msg=audit(1793494801.1:2): uid=1001\ntype=EOE msg=audit(1793494801.1:2):\n",
    );
    let (report, events) = rows(&input, None);
    assert_eq!((report.accepted, report.rejected), (2, 2));
    assert_eq!(events.len(), 2);
    let complete = events
        .iter()
        .find(|event| {
            event
                .fields()
                .field("serial")
                .and_then(SourceValue::as_text)
                == Some("2")
        })
        .unwrap();
    assert!(!complete.annotations().partial());
    assert_eq!(complete.annotations().members().len(), 2);
    let bounded = events
        .iter()
        .find(|event| {
            event
                .fields()
                .field("serial")
                .and_then(SourceValue::as_text)
                == Some("1")
        })
        .unwrap();
    assert!(bounded.annotations().partial());
    assert_eq!(bounded.annotations().members().len(), 128);
}
#[test]
fn cancellation_and_depth_or_field_limits_fail_closed() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(read(WEB, None, &cancel), Err(AppError::Cancelled)));
    assert!(!super::bounds::json_shape(
        format!("{}0{}", "[".repeat(65), "]".repeat(65)).as_bytes()
    ));
    let huge = format!(
        "{{{}}}",
        (0..1025)
            .map(|i| format!("\"key{i}\":0"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(!super::bounds::json_shape(huge.as_bytes()));
}
#[test]
fn generic_syslog_with_pri_stays_with_its_existing_module() {
    assert!(
        LinuxParser
            .detect(
                "synthetic",
                b"<34>Nov  1 01:00:00 host sshd[1]: Accepted password"
            )
            .is_none()
    );
}
