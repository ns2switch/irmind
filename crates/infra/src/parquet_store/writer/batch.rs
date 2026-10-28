use super::{AppError, Arc, ArrayRef, RecordBatch, RecordRow, StringArray, UInt64Array, storage};

pub(super) fn entity_batch(rows: &[RecordRow]) -> Result<RecordBatch, AppError> {
    let mut hashes = Vec::new();
    let mut indexes = Vec::new();
    let mut times = Vec::new();
    let mut events = Vec::new();
    let mut kinds = Vec::new();
    let mut values = Vec::new();
    for row in rows {
        for (kind, value) in &row.entity_pairs {
            hashes.push(row.hash.as_str());
            indexes.push(row.index);
            times.push(row.at.as_str());
            events.push(row.event.as_str());
            kinds.push(kind.as_str());
            values.push(value.as_str());
        }
    }
    RecordBatch::try_from_iter(vec![
        (
            "source_hash",
            Arc::new(StringArray::from(hashes)) as ArrayRef,
        ),
        (
            "record_index",
            Arc::new(UInt64Array::from(indexes)) as ArrayRef,
        ),
        ("event_time", Arc::new(StringArray::from(times)) as ArrayRef),
        ("event", Arc::new(StringArray::from(events)) as ArrayRef),
        (
            "entity_kind",
            Arc::new(StringArray::from(kinds)) as ArrayRef,
        ),
        (
            "entity_value",
            Arc::new(StringArray::from(values)) as ArrayRef,
        ),
    ])
    .map_err(storage)
}

pub(super) fn record_batch(rows: &[RecordRow]) -> Result<RecordBatch, AppError> {
    RecordBatch::try_from_iter(vec![
        (
            "source_hash",
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.hash.as_str()).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "record_index",
            Arc::new(UInt64Array::from(
                rows.iter().map(|r| r.index).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "event_time",
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.at.as_str()).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "event",
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.event.as_str()).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "text",
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.text.as_str()).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "entities",
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.entities.as_str()).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "relations",
            Arc::new(StringArray::from(
                rows.iter()
                    .map(|r| r.relations.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
    ])
    .map_err(storage)
}
