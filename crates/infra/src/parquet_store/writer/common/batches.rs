use super::{CommonRow, ObservationRow};
use crate::parquet_store::{AppError, RecordBatch, RecordRow, invalid_source, storage};
use arrow::{
    array::{ArrayRef, StringArray, UInt8Array, UInt16Array, UInt32Array, UInt64Array},
    datatypes::{Field, Schema},
};
use std::sync::Arc;

type Pair<'a> = (usize, &'a RecordRow, &'a ObservationRow);
fn pairs(rows: &[RecordRow]) -> Result<Vec<Pair<'_>>, AppError> {
    let mut pairs = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let common = row.common.as_ref().ok_or_else(invalid_source)?;
        pairs.extend(
            common
                .observations
                .iter()
                .map(|observation| (index, row, observation)),
        );
    }
    pairs.sort_by(|a, b| {
        let (ar, ao) = (a.1, a.2);
        let (br, bo) = (b.1, b.2);
        (
            &ao.kind, &ao.value, &ao.scope, ao.role, ao.field, &ar.hash, ar.index,
        )
            .cmp(&(
                &bo.kind, &bo.value, &bo.scope, bo.role, bo.field, &br.hash, br.index,
            ))
    });
    Ok(pairs)
}

pub(in crate::parquet_store::writer) fn events(
    rows: &[RecordRow],
) -> Result<RecordBatch, AppError> {
    let indices = (0..rows.len()).collect::<Vec<_>>();
    let base = super::super::batch::record_batch(rows)?;
    let base = super::super::precise::columns(&base, rows, &indices)?;
    let common = selected(rows, &indices)?;
    let mut columns = classification(&common);
    columns.extend([
        (
            "common_payload",
            Arc::new(StringArray::from(
                common
                    .iter()
                    .map(|r| r.payload.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "event_role_bits",
            Arc::new(UInt16Array::from(
                common.iter().map(|r| r.role_bits).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
    ]);
    extend(&base, columns)
}

pub(in crate::parquet_store::writer) fn entities(
    rows: &[RecordRow],
    coobservations: bool,
) -> Result<RecordBatch, AppError> {
    let pairs = pairs(rows)?;
    let indices = pairs.iter().map(|p| p.0).collect::<Vec<_>>();
    let common = selected(rows, &indices)?;
    let columns = entity_base(&pairs, coobservations);
    let base = RecordBatch::try_from_iter(columns).map_err(storage)?;
    let base = super::super::precise::columns(&base, rows, &indices)?;
    let mut columns = classification(&common);
    columns.extend(association(&pairs));
    if coobservations {
        columns.push((
            "co_observations",
            Arc::new(StringArray::from(
                common
                    .iter()
                    .map(|r| r.co_observations.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ));
    }
    extend(&base, columns)
}
fn selected<'a>(rows: &'a [RecordRow], indices: &[usize]) -> Result<Vec<&'a CommonRow>, AppError> {
    indices
        .iter()
        .map(|index| {
            rows.get(*index)
                .and_then(|r| r.common.as_ref())
                .ok_or_else(invalid_source)
        })
        .collect()
}
fn classification(rows: &[&CommonRow]) -> Vec<(&'static str, ArrayRef)> {
    vec![
        (
            "event_category_bits",
            Arc::new(UInt32Array::from(
                rows.iter().map(|r| r.categories).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "event_type_bits",
            Arc::new(UInt32Array::from(
                rows.iter().map(|r| r.types).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "event_outcome",
            Arc::new(UInt8Array::from(
                rows.iter().map(|r| r.outcome).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "event_kind",
            Arc::new(UInt8Array::from(
                rows.iter().map(|r| r.kind).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
    ]
}
fn extend(batch: &RecordBatch, extra: Vec<(&str, ArrayRef)>) -> Result<RecordBatch, AppError> {
    let mut fields = batch.schema().fields().iter().cloned().collect::<Vec<_>>();
    let mut columns = batch.columns().to_vec();
    for (name, array) in extra {
        fields.push(Arc::new(Field::new(name, array.data_type().clone(), false)));
        columns.push(array);
    }
    let metadata = std::collections::HashMap::from([(
        "irmind.common.schema".into(),
        irmind_domain::COMMON_EVENT_V1.into(),
    )]);
    RecordBatch::try_new(
        Arc::new(Schema::new(fields).with_metadata(metadata)),
        columns,
    )
    .map_err(storage)
}

fn strings<'a>(pairs: &[Pair<'a>], select: impl Fn(&Pair<'a>) -> &'a str) -> ArrayRef {
    Arc::new(StringArray::from_iter_values(pairs.iter().map(select)))
}
fn entity_base(pairs: &[Pair<'_>], coobservations: bool) -> Vec<(&'static str, ArrayRef)> {
    let mut columns = vec![
        ("source_hash", strings(pairs, |p| p.1.hash.as_str())),
        (
            "record_index",
            Arc::new(UInt64Array::from_iter_values(
                pairs.iter().map(|p| p.1.index),
            )) as ArrayRef,
        ),
        ("event_time", strings(pairs, |p| p.1.at.as_str())),
        ("entity_kind", strings(pairs, |p| p.2.kind.as_str())),
        ("entity_value", strings(pairs, |p| p.2.value.as_str())),
    ];
    columns.push(if coobservations {
        ("co_entities", strings(pairs, |p| p.1.entities.as_str()))
    } else {
        ("event", strings(pairs, |p| p.1.event.as_str()))
    });
    columns
}
fn association(pairs: &[Pair<'_>]) -> Vec<(&'static str, ArrayRef)> {
    vec![
        (
            "entity_role",
            Arc::new(UInt8Array::from_iter_values(pairs.iter().map(|p| p.2.role))) as ArrayRef,
        ),
        (
            "entity_field",
            Arc::new(UInt16Array::from_iter_values(
                pairs.iter().map(|p| p.2.field),
            )) as ArrayRef,
        ),
        ("identity_scope", strings(pairs, |p| p.2.scope.as_str())),
    ]
}
