use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1, SourceValue},
};

const FIXTURE: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-google-workspace/source/events.ndjson");

#[test]
fn native_activities_expand_without_losing_original_parameters() {
    irmind_testkit::run_log_parser_contract(
        &GoogleWorkspaceParser,
        &GoogleWorkspaceSourceDecoder,
        "events.ndjson",
        FIXTURE,
        9,
        None,
    )
    .unwrap();
    let (report, rows) = decode(FIXTURE, "events.ndjson");
    assert_eq!((report.accepted, report.rejected), (9, 0));
    assert_eq!(rows[0].origin().offset(), rows[1].origin().offset());
    assert_eq!(rows[0].origin().offset(), Some(0));
    assert_eq!(rows[1].origin().record(), 1);
    let future = rows[4].fields().field("event").unwrap();
    assert_eq!(
        future.field("name").and_then(SourceValue::as_text),
        Some("future_drive_event")
    );
    assert!(future.field("parameters").is_some());
}

#[test]
fn activities_list_pages_remain_bounded_and_have_physical_activity_offsets() {
    let first = FIXTURE.split(|byte| *byte == b'\n').next().unwrap();
    let prefix = br#"{"kind":"admin#reports#activities","items":["#;
    let bytes = [
        prefix.as_slice(),
        first,
        br#"],"nextPageToken":"synthetic"}"#,
    ]
    .concat();
    assert_eq!(
        GoogleWorkspaceParser
            .detect("page.json", &bytes)
            .unwrap()
            .value(),
        98
    );
    let (report, rows) = decode(&bytes, "page.json");
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(rows[1].origin().offset(), Some(prefix.len() as u64));
}

#[test]
fn a_malformed_subrecord_does_not_hide_another_event() {
    let document = std::str::from_utf8(FIXTURE).unwrap().replace(
        r#"{"type":"login","name":"login_success"}"#,
        r#"{"unrecognized":true}"#,
    );
    let (report, rows) = decode(document.as_bytes(), "events.ndjson");
    assert_eq!((report.accepted, report.rejected), (8, 1));
    assert!(report.samples.iter().all(|sample| sample.len() <= 256));
    assert_eq!(
        rows.last()
            .unwrap()
            .fields()
            .field("event")
            .unwrap()
            .field("name")
            .and_then(SourceValue::as_text),
        Some("delivery")
    );
}

fn decode(mut bytes: &[u8], name: &str) -> (irmind_app::ParseReport, Vec<SourceRecordV1>) {
    let source = SourceReferenceV1::file(name).unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = GoogleWorkspaceSourceDecoder
        .decode_reader(
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
            &mut |row| {
                row.inspect(|record| rows.push(record.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, rows)
}

#[test]
fn a_large_single_line_page_reaches_its_last_event() {
    let row = FIXTURE.split(|byte| *byte == b'\n').next().unwrap();
    let count = 5 * 1024 * 1024 / (row.len() + 1) + 1;
    let activity_stride = row.len() as u64 + 1;
    let prefix = br#"{"items":["#;
    let mut page = Vec::with_capacity(prefix.len() + count * (row.len() + 1) + 2);
    page.extend_from_slice(prefix);
    for index in 0..count {
        if index > 0 {
            page.push(b',');
        }
        page.extend_from_slice(row);
    }
    page.extend_from_slice(b"]}");
    let source = SourceReferenceV1::file("page.json").unwrap();
    let cancel = CancellationToken::new();
    let mut seen = 0u64;
    let report = GoogleWorkspaceSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(&page),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut page.as_slice(),
            },
            &mut |row| {
                row.inspect(|row| {
                    assert_eq!(row.origin().record(), seen);
                    assert_eq!(
                        row.origin().offset(),
                        Some(prefix.len() as u64 + (seen / 2) * activity_stride)
                    );
                });
                seen += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (2 * count, 0));
}
