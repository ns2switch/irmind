use super::*;
use arrow::{
    array::{
        ArrayRef, BooleanArray, StringArray, TimestampMicrosecondArray, UInt8Array, UInt16Array,
        UInt64Array,
    },
    datatypes::{Field, Schema},
};
use std::sync::Arc;
fn batch(indices: &[u64], times: &[Option<i64>], precise: bool, label: &str) -> RecordBatch {
    let mut columns: Vec<(&str, ArrayRef)> = vec![
        (
            "event",
            Arc::new(StringArray::from(
                (0..indices.len())
                    .map(|r| format!("{label}-{r}"))
                    .collect::<Vec<_>>(),
            )),
        ),
        (
            "source_hash",
            Arc::new(StringArray::from(vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                indices.len()
            ])),
        ),
        (
            "_irmind_source",
            Arc::new(StringArray::from(vec!["synthetic.log"; indices.len()])),
        ),
        (
            "record_index",
            Arc::new(UInt64Array::from(indices.to_vec())),
        ),
    ];
    if precise {
        columns.extend([
            (
                "_irmind_instant",
                Arc::new(TimestampMicrosecondArray::from(times.to_vec())) as ArrayRef,
            ),
            (
                "submicro_nanos",
                Arc::new(UInt16Array::from(
                    times.iter().map(|t| t.map(|_| 0)).collect::<Vec<_>>(),
                )),
            ),
            (
                "time_precision",
                Arc::new(UInt8Array::from(
                    times
                        .iter()
                        .map(|t| if t.is_some() { 3 } else { 0 })
                        .collect::<Vec<_>>(),
                )),
            ),
            (
                "time_inferred",
                Arc::new(BooleanArray::from(vec![false; indices.len()])),
            ),
        ]);
    } else {
        columns.push((
            "event_time",
            Arc::new(StringArray::from(
                times
                    .iter()
                    .map(|t| {
                        t.map_or_else(String::new, |v| {
                            chrono::DateTime::from_timestamp_micros(v)
                                .unwrap()
                                .format("%Y-%m-%dT%H:%M:%SZ")
                                .to_string()
                        })
                    })
                    .collect::<Vec<_>>(),
            )),
        ));
    }
    let schema = Schema::new(
        columns
            .iter()
            .map(|(n, a)| Field::new(*n, a.data_type().clone(), a.null_count() > 0))
            .collect::<Vec<_>>(),
    );
    RecordBatch::try_new(
        Arc::new(schema),
        columns.into_iter().map(|(_, a)| a).collect(),
    )
    .unwrap()
}
fn eager(batch: &RecordBatch, hits: &mut Vec<EventHit>, limit: usize, newest: bool, precise: bool) {
    let displayed;
    let batch = if precise {
        // Recreate the preceding reader's whole-batch display projection.
        let mut fields = batch.schema().fields().iter().cloned().collect::<Vec<_>>();
        fields.push(Arc::new(Field::new(
            "event_time",
            arrow::datatypes::DataType::Utf8,
            false,
        )));
        let times = (0..batch.num_rows())
            .map(|row| {
                crate::parquet_store::time_cell::TimeCell::from_batch(batch, row)
                    .unwrap()
                    .display()
            })
            .collect::<Vec<_>>();
        let mut columns = batch.columns().to_vec();
        columns.push(Arc::new(StringArray::from(times)));
        displayed = RecordBatch::try_new(Arc::new(Schema::new(fields)), columns).unwrap();
        &displayed
    } else {
        batch
    };
    hits.extend((0..batch.num_rows()).map(|r| EventHit::from_batch(batch, r, precise).unwrap()));
    super::super::ordered(hits, limit, newest).unwrap();
}
#[test]
fn borrowed_selection_matches_eager_stable_order_deduplication_and_all_output_bytes() {
    let base = 1_793_491_200_000_000;
    for precise in [false, true] {
        for newest in [false, true] {
            for limit in [0, 1, 2, 20, 100] {
                let first = batch(
                    &[8, 2, 4],
                    &[Some(base + 2_000_000), None, Some(base)],
                    precise,
                    "first",
                );
                let second = batch(
                    &[5, 8, 1, 7],
                    &[
                        Some(base + 1_000_000),
                        Some(base + 2_000_000),
                        Some(base),
                        None,
                    ],
                    precise,
                    "second",
                );
                let (mut expected, mut actual) = (Vec::new(), Vec::new());
                for batch in [&first, &second] {
                    eager(batch, &mut expected, limit, newest, precise);
                    let allocations =
                        retain_batch(batch, &mut actual, limit, newest, precise).unwrap();
                    assert!(allocations <= limit);
                    assert!(expected == actual);
                }
            }
        }
    }
}
#[test]
fn thousands_of_rows_materialize_only_the_retained_output() {
    let indices = (0..4096).collect::<Vec<_>>();
    let times = indices
        .iter()
        .map(|i| Some(1_793_491_200_000_000 + i64::try_from(*i).unwrap()))
        .collect::<Vec<_>>();
    let data = batch(&indices, &times, true, "dense");
    let mut hits = Vec::new();
    assert_eq!(retain_batch(&data, &mut hits, 10, true, true).unwrap(), 10);
    assert_eq!(hits.len(), 10);
    assert_eq!(hits[0].index, 4095);
}
#[test]
fn malformed_time_outside_the_retained_sample_still_fails() {
    let mut data = batch(
        &[1, 2],
        &[Some(1_793_491_201_000_000), Some(1_793_491_200_000_000)],
        true,
        "invalid",
    );
    let index = data.schema().index_of("time_precision").unwrap();
    let mut columns = data.columns().to_vec();
    columns[index] = Arc::new(UInt8Array::from(vec![3, 255]));
    data = RecordBatch::try_new(data.schema(), columns).unwrap();
    assert!(retain_batch(&data, &mut Vec::new(), 1, true, true).is_err());
}
