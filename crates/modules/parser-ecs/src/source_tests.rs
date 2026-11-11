use super::*;
use irmind_app::{
    SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1, SourceValue},
};
use std::io::Cursor;
fn decode(
    bytes: &[u8],
    cancel: &CancellationToken,
) -> (ParseReport, Vec<irmind_app::source_mapping::SourceRecordV1>) {
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let mut records = Vec::new();
    let report = EcsSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cancel,
                },
                reader: &mut Cursor::new(bytes),
            },
            &mut |record| {
                record.inspect(|r| records.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, records)
}
const EVENT: &[u8] = br#"{"@timestamp":"2026-11-01T00:00:00.123456789Z","ecs":{"version":"9.5.0"},"event":{"action":"original"},"source":{"ip":"not-yet-interpreted"},"count":123,"ok":true}"#;
#[test]
fn decoding_preserves_original_types_time_and_provenance_without_interpretation() {
    let (report, rows) = decode(EVENT, &CancellationToken::new());
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(
        rows[0].timestamp().unwrap().to_rfc3339(),
        "2026-11-01T00:00:00.123456789Z"
    );
    assert!(matches!(
        rows[0].fields().field("count"),
        Some(SourceValue::Number(_))
    ));
    assert!(matches!(
        rows[0].fields().field("ok"),
        Some(SourceValue::Boolean(true))
    ));
    assert_eq!(rows[0].origin().offset(), Some(0));
    assert!(rows[0].fields().field("result").is_none());
}
#[test]
fn oversized_first_line_is_rejected_whole_and_the_next_record_survives() {
    use std::io::Read as _;
    for size in [5u64, 50, 200].map(|mib| mib * 1024 * 1024) {
        let cancel = CancellationToken::new();
        let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
        let mut tail = vec![b'\n'];
        tail.extend_from_slice(EVENT);
        let mut reader = std::io::repeat(b'x').take(size).chain(Cursor::new(tail));
        let mut offset = None;
        let report = EcsSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &source,
                        evidence_hash: [8; 32],
                        time_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut reader,
                },
                &mut |row| {
                    row.inspect(|r| offset = r.origin().offset());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!((report.accepted, report.rejected), (1, 1));
        assert_eq!(offset, Some(size + 1));
        assert!(report.samples[0].len() <= 256);
    }
}
#[test]
fn duplicate_keys_and_deep_records_are_rejected_without_losing_later_events() {
    let mut bytes =
        br#"{"@timestamp":"2026-11-01T00:00:00Z","ecs":{"version":"9.5.0"},"x":1,"x":2}"#.to_vec();
    bytes.push(b'\n');
    bytes.extend_from_slice(format!("{{\"@timestamp\":\"2026-11-01T00:00:00Z\",\"ecs\":{{\"version\":\"9.5.0\"}},\"deep\":{}0{}}}\n", "[".repeat(40), "]".repeat(40)).as_bytes());
    bytes.extend_from_slice(EVENT);
    let (report, rows) = decode(&bytes, &CancellationToken::new());
    assert_eq!((report.accepted, report.rejected, rows.len()), (1, 2, 1));
}
#[test]
fn callback_errors_and_cancellation_propagate() {
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let metadata = SourceMetadata {
        source: &source,
        evidence_hash: [8; 32],
        time_context: None,
        cancel: &cancel,
    };
    assert!(matches!(
        EcsSourceDecoder.decode_reader(
            SourceInput {
                metadata,
                reader: &mut Cursor::new(EVENT)
            },
            &mut |_| Err(AppError::Cancelled)
        ),
        Err(AppError::Cancelled)
    ));
    cancel.cancel();
    assert!(matches!(
        EcsSourceDecoder.decode_reader(
            SourceInput {
                metadata,
                reader: &mut Cursor::new(EVENT)
            },
            &mut |_| Ok(())
        ),
        Err(AppError::Cancelled)
    ));
}
