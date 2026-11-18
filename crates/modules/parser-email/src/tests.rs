use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1, SourceValue},
};
const MULTIPART: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-email/source/multipart.eml");
fn decode(mut bytes: &[u8]) -> Result<(irmind_app::ParseReport, Vec<SourceRecordV1>), AppError> {
    let source = SourceReferenceV1::file("synthetic.eml").unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let report = EmailSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: None,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut bytes,
        },
        &mut |record| {
            record.inspect(|r| records.push(r.clone()));
            Ok(())
        },
    )?;
    Ok((report, records))
}
#[test]
fn mime_contracts_preserve_original_headers_and_attachment_hash() {
    for (name, bytes, count) in [
        ("multipart.eml", MULTIPART, 7),
        (
            "headers.eml",
            include_bytes!("../../../testkit/fixtures/parser-email/source/headers.eml").as_slice(),
            1,
        ),
        (
            "plain.eml",
            include_bytes!("../../../testkit/fixtures/parser-email/source/plain.eml").as_slice(),
            2,
        ),
    ] {
        irmind_testkit::run_log_parser_contract(
            &EmailParser,
            &EmailSourceDecoder,
            name,
            bytes,
            count,
            None,
        )
        .unwrap();
    }
}

#[test]
fn original_header_order_time_and_attachment_metadata_are_preserved() {
    let (report, records) = decode(MULTIPART).unwrap();
    assert_eq!((report.accepted, report.rejected), (7, 0));
    let root = &records[0];
    assert_eq!(root.origin().offset(), None);
    assert!(records.iter().all(|r| r.origin().offset().is_none()));
    assert!(
        matches!(root.fields().field("source_byte_offset"), Some(SourceValue::Number(n)) if n.as_str() == "0")
    );
    assert_eq!(
        root.timestamp().unwrap().instant().unix_micros(),
        1_794_918_896_000_000
    );
    let received = root
        .fields()
        .field("decoded_headers")
        .unwrap()
        .field("received")
        .unwrap();
    let hops = match received {
        SourceValue::Array(hops) => Some(hops),
        _ => None,
    }
    .unwrap();
    assert_eq!(hops.len(), 2);
    assert!(
        hops[0]
            .field("raw")
            .unwrap()
            .as_text()
            .unwrap()
            .contains("relay.example.invalid")
    );
    assert!(
        hops[1]
            .field("raw")
            .unwrap()
            .as_text()
            .unwrap()
            .contains("workstation.example.invalid")
    );
    let attachment = records
        .iter()
        .find(|r| r.fields().field("sha256").is_some())
        .unwrap();
    assert_eq!(
        attachment
            .fields()
            .field("sha256")
            .unwrap()
            .as_text()
            .unwrap(),
        irmind_app::hex(&irmind_app::sha256(
            b"Synthetic attachment; never execute or decompress.\n"
        ))
    );
    assert_eq!(
        attachment.fields().field("filename").unwrap().as_text(),
        Some("synthetic.zip")
    );
    assert!(!records.iter().any(|r| {
        r.fields()
            .field("text")
            .and_then(SourceValue::as_text)
            .is_some_and(|v| v.contains("DO_NOT_RENDER_HTML"))
    }));
    assert!(records.iter().any(|r| {
        r.fields()
            .field("html_source")
            .and_then(SourceValue::as_text)
            .is_some_and(|v| v.contains("<script>DO_NOT_RENDER_HTML</script>"))
    }));
}

#[test]
fn transformed_body_offsets_are_unavailable_and_transport_is_decoded_once() {
    let (_, records) = decode(MULTIPART).unwrap();
    let text = records
        .iter()
        .find(|r| r.fields().field("text").is_some())
        .unwrap();
    assert!(text.origin().offset().is_none());
    assert!(
        text.fields()
            .field("text")
            .unwrap()
            .as_text()
            .unwrap()
            .contains("https://portal.example.invalid/login?token=synthetic")
    );
    let plain = include_bytes!("../../../testkit/fixtures/parser-email/source/plain.eml");
    let (_, records) = decode(plain).unwrap();
    let text = records
        .iter()
        .find(|r| r.fields().field("text").is_some())
        .unwrap();
    assert!(
        text.fields()
            .field("text")
            .unwrap()
            .as_text()
            .unwrap()
            .contains("a%252Fb?x=one%26two")
    );
    assert!(text.origin().offset().is_some());
}
#[test]
fn large_text_is_complete_and_utf8_boundaries_are_preserved() {
    let body = "xé".repeat(2 * 1024 * 1024);
    let bytes = format!(
        "From: sender@example.invalid\nSubject: Synthetic\nContent-Type: text/plain; charset=utf-8\n\n{body}"
    );
    let (report, records) = decode(bytes.as_bytes()).unwrap();
    assert_eq!(report.rejected, 0);
    let restored = records
        .iter()
        .filter_map(|r| r.fields().field("text").and_then(SourceValue::as_text))
        .collect::<String>();
    assert_eq!(restored, body);
}
#[test]
fn structural_limits_and_malformed_mime_reject_the_source() {
    let too_many = format!("{}\n", "X-Synthetic: value\n".repeat(1025));
    assert!(matches!(
        decode(too_many.as_bytes()),
        Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit))
    ));
    let big_header = format!("Subject: {}\n\n", "x".repeat(65536));
    assert!(decode(big_header.as_bytes()).is_err());
    assert!(decode(b"From: a@example.invalid\nContent-Type: multipart/mixed; boundary=synthetic\n\n--synthetic\n\nunterminated").is_err());
    assert!(EmailParser.detect("synthetic.eml", b"not email").is_none());
}

#[test]
fn minimal_headers_require_analyst_selection_and_no_clock_is_invented() {
    let bytes = b"From: sender@example.invalid\nSubject: synthetic\nDate: Tue, 17 Nov 2026 12:34:56\n\ntext";
    assert_eq!(
        EmailParser.detect("message.eml", bytes).unwrap().value(),
        70
    );
    let (_, records) = decode(bytes).unwrap();
    assert!(records.iter().all(|r| r.timestamp().is_none()));
}
#[test]
fn depth_and_part_limits_reject_the_complete_message() {
    let mut deep = String::from(
        "From: sender@example.invalid\nContent-Type: multipart/mixed; boundary=b0\n\n",
    );
    for depth in 0..17 {
        deep.push_str(&format!(
            "--b{depth}\nContent-Type: multipart/mixed; boundary=b{}\n\n",
            depth + 1
        ));
    }
    deep.push_str("--b17\nContent-Type: text/plain\n\nsynthetic\n--b17--\n");
    for depth in (0..17).rev() {
        deep.push_str(&format!("--b{depth}--\n"));
    }
    assert!(matches!(
        decode(deep.as_bytes()),
        Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit))
    ));
    let mut parts = String::from(
        "From: sender@example.invalid\nContent-Type: multipart/mixed; boundary=part\n\n",
    );
    parts.push_str(&"--part\nContent-Type: text/plain\n\nsynthetic\n".repeat(256));
    parts.push_str("--part--\n");
    assert!(matches!(
        decode(parts.as_bytes()),
        Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit))
    ));
}
#[test]
fn source_size_and_reader_cancellation_fail_without_emitting_records() {
    use std::io::Read;
    let source = SourceReferenceV1::file("synthetic.eml").unwrap();
    let cancel = CancellationToken::new();
    let mut reader = std::io::repeat(b'x').take(32 * 1024 * 1024 + 1);
    let mut emitted = false;
    let result = EmailSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: [1; 32],
                time_context: None,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut reader,
        },
        &mut |_| {
            emitted = true;
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit))
    ));
    assert!(!emitted);
    struct Cancelling<'a>(&'a CancellationToken);
    impl Read for Cancelling<'_> {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.0.cancel();
            Err(std::io::Error::other("synthetic cancellation"))
        }
    }
    let cancel = CancellationToken::new();
    let result = EmailSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: [1; 32],
                time_context: None,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut Cancelling(&cancel),
        },
        &mut |_| {
            emitted = true;
            Ok(())
        },
    );
    assert!(matches!(result, Err(AppError::Cancelled)));
    assert!(!emitted);
}

#[test]
fn duplicate_dates_are_retained_without_choosing_an_event_time() {
    let bytes = b"From: a@example.invalid\r\nSubject: synthetic\r\nDate: Tue, 17 Nov 2026 12:00:00 +0000\r\nDate: Wed, 18 Nov 2026 13:00:00 +0000\r\n\r\nbody";
    let (_, records) = decode(bytes).unwrap();
    assert!(records.iter().all(|r| r.timestamp().is_none()));
    assert!(
        matches!(records[0].fields().field("decoded_headers").and_then(|h| h.field("date")), Some(SourceValue::Array(values)) if values.len() == 2)
    );
}

#[test]
fn other_text_media_types_retain_the_complete_body_as_untrusted_text() {
    let bytes = b"From: a@example.invalid\r\nSubject: synthetic\r\nMessage-ID: <calendar@example.invalid>\r\nContent-Type: text/calendar; charset=utf-8\r\n\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
    let (report, records) = decode(bytes).unwrap();
    assert_eq!(report.accepted, 2);
    let body = records[1].fields();
    assert_eq!(
        body.field("declared_type").and_then(SourceValue::as_text),
        Some("text/calendar")
    );
    assert_eq!(
        body.field("text").and_then(SourceValue::as_text),
        Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n")
    );
}
