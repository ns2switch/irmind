#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{
    SourceDecoder,
    source_mapping::{
        SourceFileInput, SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1,
    },
};
fn decoded(name: &str, bytes: &[u8]) -> (ParseReport, Vec<SourceRecordV1>) {
    let reference = SourceReferenceV1::file(name).unwrap();
    let cancel = CancellationToken::new();
    let mut rows = vec![];
    let report = OcsfSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: [9; 32],
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut Cursor::new(bytes),
            },
            &mut |row| {
                row.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, rows)
}
#[test]
fn original_types_time_and_unmapped_fields_survive_without_classification() {
    let raw = event(3002, 3);
    let (report, rows) = decoded("events.ndjson", raw.as_bytes());
    assert_eq!((report.accepted, report.rejected), (1, 0));
    let row = &rows[0];
    assert!(matches!(
        row.fields().field("class_uid"),
        Some(irmind_domain::SourceValue::Number(_))
    ));
    assert_eq!(
        row.fields()
            .field("unmapped")
            .unwrap()
            .field("marker")
            .unwrap()
            .as_text(),
        Some("retained")
    );
    assert_eq!(
        row.timestamp().unwrap().precision(),
        irmind_domain::TimePrecision::Millisecond
    );
    assert!(row.fields().field("event.category").is_none());
}
#[test]
fn bad_line_is_counted_and_original_row_pointer_is_not_an_accepted_ordinal() {
    let raw = format!("{{bad}}\n{}\n", event(3002, 3));
    let (report, rows) = decoded("events.ndjson", raw.as_bytes());
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(rows[0].origin().record(), 0);
    assert_eq!(rows[0].origin().offset(), Some(6));
    assert_eq!(rows[0].annotations().members()[0].ordinal, 1);
    assert!(report.samples.iter().all(|s| s.len() <= 256));
}
#[test]
fn nanosecond_datetime_is_preserved_and_conflicting_time_fields_are_rejected() {
    let mut value: serde_json::Value = serde_json::from_str(&event(3002, 3)).unwrap();
    value.as_object_mut().unwrap().remove("time");
    value["time_dt"] = serde_json::json!("2026-01-02T03:04:05.123456789Z");
    let (_, rows) = decoded("events.json", value.to_string().as_bytes());
    assert_eq!(rows[0].timestamp().unwrap().instant().submicro_nanos(), 789);
    value["time"] = serde_json::json!(0);
    let (report, rows) = decoded("events.ndjson", value.to_string().as_bytes());
    assert_eq!((report.accepted, report.rejected, rows.len()), (0, 1, 0));
}
#[test]
fn flat_event_events_field_is_data_and_does_not_select_container_framing() {
    let mut value: serde_json::Value = serde_json::from_str(&event(3002, 3)).unwrap();
    value["events"] = serde_json::json!([{"untrusted":"retained"}]);
    let raw = serde_json::to_string_pretty(&value).unwrap();
    let (report, rows) = decoded("events.json", raw.as_bytes());
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert!(rows[0].fields().field("events").is_some());
}
#[test]
fn a_single_line_array_larger_than_four_mib_streams_every_event() {
    let record = event(3002, 3);
    let count = 5 * 1024 * 1024 / record.len() + 1;
    let raw = format!(
        "[{}]",
        std::iter::repeat_n(record.as_str(), count)
            .collect::<Vec<_>>()
            .join(",")
    );
    let reference = SourceReferenceV1::file("events.json").unwrap();
    let cancel = CancellationToken::new();
    let mut seen = 0;
    let report = OcsfSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: [9; 32],
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut Cursor::new(raw),
            },
            &mut |_| {
                seen += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected, seen), (count, 0, count));
}
#[test]
fn cancellation_and_consumer_failure_are_not_rejected_rows() {
    let reference = SourceReferenceV1::file("events.ndjson").unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = OcsfSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: [9; 32],
                time_context: None,
                cancel: &cancel,
            },
            reader: &mut Cursor::new(event(3002, 3)),
        },
        &mut |_| Ok(()),
    );
    assert!(matches!(result, Err(AppError::Cancelled)));
    let active = CancellationToken::new();
    let result = OcsfSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: [9; 32],
                time_context: None,
                cancel: &active,
            },
            reader: &mut Cursor::new(event(3002, 3)),
        },
        &mut |_| Err(AppError::Cancelled),
    );
    assert!(matches!(result, Err(AppError::Cancelled)));
}
#[test]
fn local_parquet_uses_the_original_handle_without_a_temporary_copy_or_fake_offset() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source.parquet");
    let metadata = StructArray::from(vec![(
        Arc::new(Field::new("version", DataType::Utf8, false)),
        Arc::new(StringArray::from(vec!["1.4.0"])) as ArrayRef,
    )]);
    let schema = Arc::new(Schema::new(vec![
        Field::new("class_uid", DataType::Int64, false),
        Field::new("category_uid", DataType::Int64, false),
        Field::new("metadata", metadata.data_type().clone(), false),
        Field::new("time", DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![3002])) as ArrayRef,
            Arc::new(Int64Array::from(vec![3])),
            Arc::new(metadata),
            Arc::new(Int64Array::from(vec![1_767_323_045_000_i64])),
        ],
    )
    .unwrap();
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut writer = ArrowWriter::try_new(file.try_clone().unwrap(), schema, None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    let reference = SourceReferenceV1::file("source.parquet").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = vec![];
    let report = OcsfSourceDecoder
        .decode_local_file(
            SourceFileInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: [9; 32],
                    time_context: None,
                    cancel: &cancel,
                },
                file: &mut file,
            },
            &mut |row| {
                row.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    assert_eq!(rows[0].origin().offset(), None);
    assert_eq!(rows[0].annotations().members()[0].offset, None);
}

#[test]
fn oversized_whitespace_prefix_is_counted_without_losing_later_rows() {
    let row = format!("{}\n", event(3002, 3));
    let input = format!("{row}{}{row}{row}", " ".repeat(5 * 1024 * 1024));
    let (report, rows) = decoded("synthetic.ndjson", input.as_bytes());
    assert_eq!((report.accepted, report.rejected), (2, 1));
    assert_eq!(rows[1].annotations().members()[0].ordinal, 2);
    assert_eq!(
        rows[1].origin().offset(),
        Some((5 * 1024 * 1024 + 2 * row.len()) as u64)
    );
}
