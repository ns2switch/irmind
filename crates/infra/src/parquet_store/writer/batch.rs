use super::{AppError, Arc, ArrayRef, RecordBatch, RecordRow, StringArray, UInt64Array, storage};

fn pairs(rows: &[RecordRow], sorted: bool) -> Vec<(usize, usize)> {
    let mut pairs = rows
        .iter()
        .enumerate()
        .flat_map(|(row, value)| (0..value.entity_pairs.len()).map(move |entity| (row, entity)))
        .collect::<Vec<_>>();
    if sorted {
        pairs.sort_by(|left, right| {
            let a = &rows[left.0].entity_pairs[left.1];
            let b = &rows[right.0].entity_pairs[right.1];
            a.cmp(b)
                .then_with(|| rows[left.0].hash.cmp(&rows[right.0].hash))
                .then_with(|| rows[left.0].index.cmp(&rows[right.0].index))
        });
    }
    pairs
}

pub(super) fn entity_batch(rows: &[RecordRow], sorted: bool) -> Result<RecordBatch, AppError> {
    let mut hashes = Vec::new();
    let mut indexes = Vec::new();
    let mut times = Vec::new();
    let mut events = Vec::new();
    let mut kinds = Vec::new();
    let mut values = Vec::new();
    for (row, entity) in pairs(rows, sorted) {
        let record = &rows[row];
        let (kind, value) = &record.entity_pairs[entity];
        hashes.push(record.hash.as_str());
        indexes.push(record.index);
        times.push(record.at.as_str());
        events.push(record.event.as_str());
        kinds.push(kind.as_str());
        values.push(value.as_str());
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

pub(super) fn coobservation_batch(rows: &[RecordRow]) -> Result<RecordBatch, AppError> {
    let pairs = pairs(rows, true);
    RecordBatch::try_from_iter(vec![
        (
            "source_hash",
            Arc::new(StringArray::from(
                pairs
                    .iter()
                    .map(|(row, _)| rows[*row].hash.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "record_index",
            Arc::new(UInt64Array::from(
                pairs
                    .iter()
                    .map(|(row, _)| rows[*row].index)
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "event_time",
            Arc::new(StringArray::from(
                pairs
                    .iter()
                    .map(|(row, _)| rows[*row].at.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "entity_kind",
            Arc::new(StringArray::from(
                pairs
                    .iter()
                    .map(|(row, entity)| rows[*row].entity_pairs[*entity].0.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "entity_value",
            Arc::new(StringArray::from(
                pairs
                    .iter()
                    .map(|(row, entity)| rows[*row].entity_pairs[*entity].1.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "co_entities",
            Arc::new(StringArray::from(
                pairs
                    .iter()
                    .map(|(row, _)| rows[*row].entities.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
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
