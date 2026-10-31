use super::*;
use arrow::{
    array::{Array, ArrayRef, Int64Array, StringArray, StructArray},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use parquet::arrow::ArrowWriter;
use std::io::{Seek, SeekFrom};
use std::sync::Arc;

fn event(class_uid: u64, category_uid: u64) -> String {
    serde_json::json!({
        "class_uid": class_uid,
        "category_uid": category_uid,
        "metadata": {"version": "1.4.0"},
        "time": 1_767_323_045_000_i64,
        "activity_name": "Synthetic activity",
        "device": {"hostname": "lab-host"},
        "actor": {"user": {"name": "alice"}},
        "src_endpoint": {"ip": "192.0.2.1", "port": 1234},
        "dst_endpoint": {"ip": "198.51.100.2", "port": 443},
        "process": {"name": "test", "cmd_line": "echo synthetic"},
        "file": {"path": "/tmp/synthetic"},
        "finding_info": {"title": "Synthetic finding"},
        "cloud": {"account": {"uid": "test-account"}, "provider": "aws", "region": "eu-test-1"},
        "unmapped": {"marker": "retained"}
    })
    .to_string()
}

#[test]
fn six_supported_classes_detect_and_map() -> Result<(), AppError> {
    for (class_uid, category_uid) in [
        (1001, 1),
        (1007, 1),
        (2004, 2),
        (3002, 3),
        (4001, 4),
        (6003, 6),
    ] {
        let input = event(class_uid, category_uid);
        assert_eq!(
            OcsfParser
                .detect("episode.ndjson", input.as_bytes())
                .map(ParserConfidence::value),
            Some(95)
        );
        let mut records = Vec::new();
        OcsfParser.parse_each(
            "episode.ndjson",
            input.as_bytes(),
            &CancellationToken::new(),
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )?;
        assert_eq!(records.len(), 1);
        records[0].inspect(|record| {
            assert_eq!(record.at, "2026-01-02T03:04:05Z");
            assert!(
                record
                    .entities
                    .contains(&("host".into(), "lab-host".into()))
            );
            assert!(record.text.contains("retained"));
        });
    }
    Ok(())
}

#[test]
fn malformed_line_is_counted_without_losing_later_event() -> Result<(), AppError> {
    let input = format!("{{bad}}\n{}\n", event(3002, 3));
    let mut records = Vec::new();
    let report = OcsfParser.parse_reader_report(
        "episode.ndjson",
        &mut Cursor::new(input),
        [8; 32],
        &CancellationToken::new(),
        &mut |record| {
            records.push(record);
            Ok(())
        },
    )?;
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(records.len(), 1);
    Ok(())
}

#[test]
fn multiline_json_is_detected_and_parsed() -> Result<(), AppError> {
    let input = serde_json::to_string_pretty(
        &serde_json::from_str::<serde_json::Value>(&event(3002, 3))
            .map_err(|_| policy_error("invalid synthetic fixture"))?,
    )
    .map_err(|_| policy_error("cannot serialize synthetic fixture"))?;
    assert_eq!(
        OcsfParser
            .detect("episode.json", input.as_bytes())
            .map(ParserConfidence::value),
        Some(95)
    );
    let mut records = Vec::new();
    let report = OcsfParser.parse_reader_report(
        "episode.json",
        &mut Cursor::new(input),
        [4; 32],
        &CancellationToken::new(),
        &mut |record| {
            records.push(record);
            Ok(())
        },
    )?;
    assert_eq!((report.accepted, report.rejected), (1, 0));
    Ok(())
}

#[test]
fn incomplete_line_does_not_swallow_the_next_record() -> Result<(), AppError> {
    let input = format!("{{\"class_uid\":\n{}\n", event(3002, 3));
    let report = OcsfParser.parse_reader_report(
        "episode.ndjson",
        &mut Cursor::new(input),
        [5; 32],
        &CancellationToken::new(),
        &mut |_| Ok(()),
    )?;
    assert_eq!((report.accepted, report.rejected), (1, 1));
    Ok(())
}

#[test]
fn excessive_field_count_is_rejected() -> Result<(), AppError> {
    let mut value = serde_json::from_str::<serde_json::Value>(&event(3002, 3))
        .map_err(|_| policy_error("invalid synthetic fixture"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| policy_error("invalid synthetic fixture"))?;
    for index in 0..1024 {
        object.insert(format!("extra_{index}"), serde_json::Value::Null);
    }
    let report = OcsfParser.parse_reader_report(
        "episode.ndjson",
        &mut Cursor::new(value.to_string()),
        [6; 32],
        &CancellationToken::new(),
        &mut |_| Ok(()),
    )?;
    assert_eq!((report.accepted, report.rejected), (0, 1));
    Ok(())
}

#[test]
fn parquet_input_uses_bounded_private_spool() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = StructArray::from(vec![(
        Arc::new(Field::new("version", DataType::Utf8, false)),
        Arc::new(StringArray::from(vec!["1.4.0"])) as ArrayRef,
    )]);
    let schema = Arc::new(Schema::new(vec![
        Field::new("class_uid", DataType::Int64, false),
        Field::new("category_uid", DataType::Int64, false),
        Field::new("metadata", metadata.data_type().clone(), false),
        Field::new("time", DataType::Int64, false),
        Field::new("activity_name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![3002])) as ArrayRef,
            Arc::new(Int64Array::from(vec![3])) as ArrayRef,
            Arc::new(metadata) as ArrayRef,
            Arc::new(Int64Array::from(vec![1_767_323_045_000_i64])) as ArrayRef,
            Arc::new(StringArray::from(vec!["Synthetic activity"])) as ArrayRef,
        ],
    )?;
    let mut file = tempfile::tempfile()?;
    let mut writer = ArrowWriter::try_new(file.try_clone()?, schema, None)?;
    writer.write(&batch)?;
    writer.close()?;
    file.seek(SeekFrom::Start(0))?;
    let mut records = Vec::new();
    let count = OcsfParser.parse_reader(
        "episode.parquet",
        &mut file,
        [9; 32],
        &CancellationToken::new(),
        &mut |record| {
            records.push(record);
            Ok(())
        },
    )?;
    assert_eq!(count, 1);
    assert_eq!(records.len(), 1);
    Ok(())
}

#[test]
fn oversized_parquet_footer_is_rejected_before_decoder_allocation() {
    let mut forged = b"PAR1".to_vec();
    forged.extend_from_slice(&u32::MAX.to_le_bytes());
    forged.extend_from_slice(b"PAR1");
    let result = OcsfParser.parse_reader(
        "forged.parquet",
        &mut Cursor::new(forged),
        [0; 32],
        &CancellationToken::new(),
        &mut |_| Ok(()),
    );
    assert!(result.is_err());
}

#[test]
fn oversized_parquet_row_keeps_only_a_bounded_sample() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = StructArray::from(vec![(
        Arc::new(Field::new("version", DataType::Utf8, false)),
        Arc::new(StringArray::from(vec!["1.4.0"])) as ArrayRef,
    )]);
    let schema = Arc::new(Schema::new(vec![
        Field::new("class_uid", DataType::Int64, false),
        Field::new("category_uid", DataType::Int64, false),
        Field::new("metadata", metadata.data_type().clone(), false),
        Field::new("time", DataType::Int64, false),
        Field::new("activity_name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![3002])) as ArrayRef,
            Arc::new(Int64Array::from(vec![3])) as ArrayRef,
            Arc::new(metadata) as ArrayRef,
            Arc::new(Int64Array::from(vec![1_767_323_045_000_i64])) as ArrayRef,
            Arc::new(StringArray::from(vec!["x".repeat(4 * 1024 * 1024)])) as ArrayRef,
        ],
    )?;
    let mut file = tempfile::tempfile()?;
    let mut writer = ArrowWriter::try_new(file.try_clone()?, schema, None)?;
    writer.write(&batch)?;
    writer.close()?;
    file.seek(SeekFrom::Start(0))?;
    let report = OcsfParser.parse_reader_report(
        "oversized.parquet",
        &mut file,
        [7; 32],
        &CancellationToken::new(),
        &mut |_| Ok(()),
    )?;
    assert_eq!((report.accepted, report.rejected), (0, 1));
    assert_eq!(report.samples.len(), 1);
    assert!(report.samples[0].len() <= 256);
    Ok(())
}
