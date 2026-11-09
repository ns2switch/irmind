use super::*;
use irmind_app::source_mapping::SourceInput;
use irmind_domain::SourceReferenceV1;
fn decoded(
    bytes: &[u8],
    context: Option<&irmind_app::ParserTimeContext>,
) -> (ParseReport, Vec<SourceRecordV1>) {
    let cancel = irmind_app::CancellationToken::new();
    let mut rows = Vec::new();
    let report = LinuxSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &SourceReferenceV1::file("synthetic.log").unwrap(),
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: context,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |r| {
                r.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, rows)
}
#[test]
fn auth_framing_preserves_original_tokens_without_outcome_or_roles() {
    let (report,rows)=decoded(b"2026-11-01T00:00:00Z host-a sshd[42]: Failed password for alice from 203.0.113.77 port 2222 ssh2\n",None);
    assert_eq!((report.accepted, report.rejected), (1, 0));
    let row = &rows[0];
    assert_eq!(
        row.fields()
            .field("sshd")
            .unwrap()
            .field("verb")
            .unwrap()
            .as_text(),
        Some("Failed")
    );
    assert_eq!(
        row.fields()
            .field("sshd")
            .unwrap()
            .field("user")
            .unwrap()
            .as_text(),
        Some("alice")
    );
    assert!(row.fields().field("outcome").is_none());
    assert_eq!(row.origin().offset(), Some(0));
}
#[test]
fn classic_auth_requires_confirmed_context_and_deterministic_rollover() {
    let context =
        irmind_app::ParserTimeContext::new(2026, 0, true, irmind_app::ParserTimeBasis::Analyst)
            .unwrap();
    let (_,rows)=decoded(b"Dec 31 23:59:59 h sshd[1]: Failed password for alice from 203.0.113.1 port 22 ssh2\nJan  1 00:00:00 h sshd[1]: Accepted password for alice from 203.0.113.1 port 22 ssh2\n",Some(&context));
    assert_eq!(rows.len(), 2);
    assert!(
        rows[1]
            .timestamp()
            .unwrap()
            .to_rfc3339()
            .starts_with("2027-01-01")
    );
    assert!(rows.iter().all(|r| r.timestamp().unwrap().inferred()));
}
#[test]
fn audit_members_keep_raw_fields_and_locations_and_partial_eof() {
    let bytes=b"type=SYSCALL msg=audit(1793491200.123456789:1): arch=c000003e syscall=59 success=yes uid=0 auid=1000 pid=42\ntype=EXECVE msg=audit(1793491200.123456789:1): argc=1 a0=6964\ntype=EOE msg=audit(1793491200.123456789:1):\ntype=SYSCALL msg=audit(1793491201.1:2): syscall=59 success=no pid=42\n";
    let (report, rows) = decoded(bytes, None);
    assert_eq!(report.accepted, 2);
    assert!(!rows[0].annotations().partial());
    assert!(rows[1].annotations().partial());
    assert_eq!(rows[0].annotations().members().len(), 3);
    assert_eq!(rows[0].origin().offset(), None);
    assert_eq!(rows[0].timestamp().unwrap().instant().submicro_nanos(), 789);
    assert!(rows[0].fields().field("outcome").is_none());
}
#[test]
fn http_and_journal_values_remain_original_and_unknown_to_the_decoder() {
    let (_, rows) = decoded(
        b"203.0.113.77 - alice [01/Nov/2026:00:00:00 +0000] \"GET /synthetic HTTP/1.1\" 403 12\n",
        None,
    );
    assert_eq!(
        match rows[0].fields().field("status").unwrap() {
            irmind_domain::SourceValue::Number(n) => Some(n.as_str()),
            _ => None,
        },
        Some("403")
    );
    assert!(rows[0].fields().field("outcome").is_none());
    let (_,rows)=decoded(b"{\"__REALTIME_TIMESTAMP\":\"1793491200123456\",\"_PID\":\"42\",\"MESSAGE\":\"failure is just text\"}\n",None);
    assert_eq!(
        rows[0].timestamp().unwrap().instant().unix_micros(),
        1_793_491_200_123_456
    );
}

#[test]
fn audit_numeric_fields_are_not_hex_strings_and_a_bad_member_marks_partial() {
    let bytes=b"type=SYSCALL msg=audit(1793491200.123:1): uid=1000 pid=42 success=yes\ntype=EXECVE msg=audit(1793491200.123:1): argc=1 a0=6964\ntype=EXECVE msg=audit(1793491200.123:1): argc=1 argc=2\ntype=EOE msg=audit(1793491200.123:1):\n";
    let (report, rows) = decoded(bytes, None);
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert!(rows[0].annotations().partial());
    let values = match rows[0].fields().field("records").unwrap() {
        irmind_domain::SourceValue::Array(rows) => Some(rows),
        _ => None,
    }
    .unwrap();
    assert_eq!(values[0].field("uid").unwrap().as_text(), Some("1000"));
    assert_eq!(values[0].field("pid").unwrap().as_text(), Some("42"));
    assert_eq!(values[1].field("a0").unwrap().as_text(), Some("id"));
    assert_eq!(
        rows[0].timestamp().unwrap().precision(),
        irmind_domain::TimePrecision::Millisecond
    );
}

#[test]
fn audit_non_utf8_arguments_keep_their_binary_source_type() {
    let (_,rows)=decoded(b"type=EXECVE msg=audit(1793491200.123:1): argc=1 a0=fffe\ntype=EOE msg=audit(1793491200.123:1):\n",None);
    let records = match rows[0].fields().field("records").unwrap() {
        irmind_domain::SourceValue::Array(rows) => Some(rows),
        _ => None,
    }
    .unwrap();
    assert_eq!(
        records[0].field("a0"),
        Some(&irmind_domain::SourceValue::Bytes(vec![255, 254]))
    );
}

#[test]
fn module_registration_exposes_its_single_complete_source_decoder() {
    let mut registry = irmind_app::modules::ModuleRegistry::new();
    registry
        .register(
            Box::<crate::LinuxParser>::default(),
            &irmind_app::modules::ModuleConfig::new(),
        )
        .unwrap();
    let catalog = registry.mapping_catalog().unwrap();
    assert!(catalog.supports_decoder("parser-linux", "linux-source-v1"));
}

#[test]
fn rejected_journal_members_do_not_hide_the_next_valid_record() {
    let mut bytes = b"{\"__REALTIME_TIMESTAMP\":\"1793491200123456\",\"MESSAGE\":\"".to_vec();
    bytes.resize(bounds::MAX_LINE + 4096, b'x');
    bytes.extend_from_slice(
        b"\"}\n{\"__REALTIME_TIMESTAMP\":\"1793491200123457\",\"MESSAGE\":\"next\"}\n",
    );
    let (report, rows) = decoded(&bytes, None);
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(
        rows[0].fields().field("MESSAGE").unwrap().as_text(),
        Some("next")
    );
    assert_eq!(
        rows[0].annotations().raw(),
        Some("{\"__REALTIME_TIMESTAMP\":\"1793491200123457\",\"MESSAGE\":\"next\"}")
    );
    assert_eq!(
        rows[0].origin().offset(),
        Some((bounds::MAX_LINE + 4099) as u64)
    );
    assert!(report.samples.iter().all(|s| s.len() <= 256));
}

#[test]
fn downstream_cancellation_is_propagated_without_consuming_later_records() {
    let bytes = b"{\"__REALTIME_TIMESTAMP\":\"1793491200123456\"}\n{\"__REALTIME_TIMESTAMP\":\"1793491200123457\"}\n";
    let cancel = irmind_app::CancellationToken::new();
    let mut calls = 0;
    let result = LinuxSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &SourceReferenceV1::file("journal.jsonl").unwrap(),
                evidence_hash: irmind_app::sha256(bytes),
                time_context: None,
                cancel: &cancel,
            },
            reader: &mut std::io::Cursor::new(bytes),
        },
        &mut |_| {
            calls += 1;
            Err(AppError::Cancelled)
        },
    );
    assert!(matches!(result, Err(AppError::Cancelled)));
    assert_eq!(calls, 1);
}
