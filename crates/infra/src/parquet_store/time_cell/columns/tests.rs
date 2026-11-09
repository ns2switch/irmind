#![allow(clippy::unwrap_used)]
use super::*;
use arrow::array::{ArrayRef, UInt64Array};
use std::sync::Arc;

fn batch() -> (RecordBatch, Vec<Option<IndexedTime>>) {
    let times = [
        Some("1969-12-31T23:59:59.999999900Z"),
        Some("2026-11-01T00:00:00.123456789Z"),
        Some("2026-11-01T00:00:00Z"),
        None,
    ]
    .map(|value| value.map(|v| IndexedTime::from_rfc3339(v, false).unwrap()));
    let values = times
        .iter()
        .map(|v| v.map(|t| t.instant().unix_micros()))
        .collect::<Vec<_>>();
    let residual = times
        .iter()
        .map(|v| v.map(|t| t.instant().submicro_nanos()))
        .collect::<Vec<_>>();
    let precision = times
        .iter()
        .map(|v| v.map_or(0, |t| t.precision().code()))
        .collect::<Vec<_>>();
    let raw = RecordBatch::try_from_iter([
        (
            "event_time",
            Arc::new(TimestampMicrosecondArray::from(values).with_timezone("UTC")) as ArrayRef,
        ),
        ("submicro_nanos", Arc::new(UInt16Array::from(residual))),
        ("time_precision", Arc::new(UInt8Array::from(precision))),
        (
            "time_inferred",
            Arc::new(BooleanArray::from(vec![false; 4])),
        ),
        ("source_hash", Arc::new(StringArray::from(vec!["ab"; 4]))),
        (
            "record_index",
            Arc::new(UInt64Array::from(vec![0, 1, 2, 3])),
        ),
    ])
    .unwrap();
    (raw, times.to_vec())
}

#[test]
fn cached_physical_columns_preserve_negative_nanos_unknown_and_precision() {
    let (batch, expected) = batch();
    let columns = TimeColumns::new(&batch).unwrap();
    let rows = super::super::borrowed::BorrowedRows::new(&batch).unwrap();
    for (row, expected) in expected.into_iter().enumerate() {
        assert_eq!(columns.at(row).unwrap(), expected);
        assert_eq!(rows.at(row).unwrap().to_owned().time, expected);
    }
}

#[test]
fn cached_time_view_rejects_each_invalid_precision_and_unknown_time_encoding() {
    let (batch, _) = batch();
    for (name, replacement, row) in [
        (
            "time_precision",
            Arc::new(UInt8Array::from(vec![255, 1, 1, 0])) as ArrayRef,
            0,
        ),
        (
            "submicro_nanos",
            Arc::new(UInt16Array::from(vec![None, Some(0), Some(0), None])),
            0,
        ),
        (
            "submicro_nanos",
            Arc::new(UInt16Array::from(vec![
                Some(900),
                Some(789),
                Some(0),
                Some(0),
            ])),
            3,
        ),
        (
            "time_inferred",
            Arc::new(BooleanArray::from(vec![
                Some(false),
                Some(false),
                Some(false),
                None,
            ])),
            3,
        ),
    ] {
        let mut columns = batch.columns().to_vec();
        columns[batch.schema().index_of(name).unwrap()] = replacement;
        let changed = RecordBatch::try_from_iter(
            batch
                .schema()
                .fields()
                .iter()
                .map(|field| field.name().as_str())
                .zip(columns),
        )
        .unwrap();
        assert!(TimeColumns::new(&changed).unwrap().at(row).is_err());
        assert!(super::super::validate_times(&changed).is_err());
    }
}

#[test]
fn source_unit_cache_checks_transitions_repeated_sources_and_later_batches() {
    let make = |hashes: Vec<&str>, offsets: Vec<Option<u64>>| {
        RecordBatch::try_from_iter([
            (
                "source_hash",
                Arc::new(StringArray::from(hashes)) as ArrayRef,
            ),
            ("source_offset", Arc::new(UInt64Array::from(offsets))),
        ])
        .unwrap()
    };
    let mut modes = std::collections::BTreeMap::new();
    let valid = make(
        vec!["a", "a", "b", "a"],
        vec![Some(0), Some(1), None, Some(2)],
    );
    super::super::validate_source_units(&valid, &mut modes).unwrap();
    assert_eq!(
        modes,
        std::collections::BTreeMap::from([("a".into(), true), ("b".into(), false)])
    );
    let changed = make(vec!["a", "a"], vec![Some(0), None]);
    assert!(super::super::validate_source_units(&changed, &mut modes).is_err());
    let interleaved = make(vec!["a", "b", "a"], vec![Some(0), None, None]);
    assert!(super::super::validate_source_units(&interleaved, &mut modes).is_err());
    assert!(
        super::super::validate_source_units(&make(vec!["b"], vec![Some(0)]), &mut modes).is_err()
    );
}
