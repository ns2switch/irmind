use super::{AppError, GraphRecord, Tainted, Transaction, storage, terms};
use crate::graph_duckdb::profile::{GraphInsertProfile, GraphPhase, measure};
use duckdb::Appender;
use duckdb::arrow::array::{Int64Builder, StringBuilder};
use duckdb::arrow::datatypes::{DataType, Field, Schema};
use duckdb::arrow::record_batch::RecordBatch;
use irmind_app::CancellationToken;
use std::sync::Arc;

const TERM_BATCH_ROWS: usize = 16_384;

fn each_record(
    records: &[Tainted<GraphRecord>],
    mut append: impl FnMut(&GraphRecord) -> Result<(), AppError>,
) -> Result<(), AppError> {
    for tainted in records {
        let mut outcome = Ok(());
        tainted.inspect(|record| outcome = append(record));
        outcome?;
    }
    Ok(())
}

fn index(record: &GraphRecord) -> Result<i64, AppError> {
    i64::try_from(record.index).map_err(storage)
}

pub(super) fn insert_batch(
    tx: &Transaction<'_>,
    hash: &str,
    records: &[Tainted<GraphRecord>],
    cancel: &CancellationToken,
    profile: Option<&GraphInsertProfile>,
) -> Result<(), AppError> {
    if records.is_empty() {
        return Ok(());
    }
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    measure(profile, GraphPhase::Events, || {
        append_events(tx, hash, records)
    })?;
    measure(profile, GraphPhase::Texts, || {
        append_texts(tx, hash, records)
    })?;
    measure(profile, GraphPhase::Terms, || {
        append_terms(tx, hash, records, cancel)
    })?;
    measure(profile, GraphPhase::Observations, || {
        append_observations(tx, hash, records)
    })?;
    measure(profile, GraphPhase::Relations, || {
        append_relations(tx, hash, records)
    })?;
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    Ok(())
}

fn append_events(
    tx: &Transaction<'_>,
    hash: &str,
    records: &[Tainted<GraphRecord>],
) -> Result<(), AppError> {
    let mut appender = tx.appender("events").map_err(storage)?;
    each_record(records, |record| {
        appender
            .append_row((
                hash,
                index(record)?,
                record.at.as_str(),
                record.event.as_str(),
            ))
            .map_err(storage)
    })?;
    appender.flush().map_err(storage)
}

fn append_texts(
    tx: &Transaction<'_>,
    hash: &str,
    records: &[Tainted<GraphRecord>],
) -> Result<(), AppError> {
    let mut appender = tx.appender("record_texts").map_err(storage)?;
    each_record(records, |record| {
        appender
            .append_row((hash, index(record)?, record.text.as_str()))
            .map_err(storage)
    })?;
    appender.flush().map_err(storage)
}

fn append_terms(
    tx: &Transaction<'_>,
    hash: &str,
    records: &[Tainted<GraphRecord>],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let mut appender = tx.appender("record_terms").map_err(storage)?;
    let mut term_values = StringBuilder::new();
    let mut hashes = StringBuilder::new();
    let mut indices = Int64Builder::new();
    let mut rows = 0usize;
    each_record(records, |record| {
        let record_index = index(record)?;
        for term in terms(&record.text)? {
            if rows.is_multiple_of(8_192) && cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            term_values.append_value(term);
            hashes.append_value(hash);
            indices.append_value(record_index);
            rows += 1;
            if rows == TERM_BATCH_ROWS {
                append_term_batch(&mut appender, &mut term_values, &mut hashes, &mut indices)?;
                rows = 0;
            }
        }
        Ok(())
    })?;
    if rows > 0 {
        append_term_batch(&mut appender, &mut term_values, &mut hashes, &mut indices)?;
    }
    appender.flush().map_err(storage)
}

fn append_term_batch(
    appender: &mut Appender<'_>,
    terms: &mut StringBuilder,
    hashes: &mut StringBuilder,
    indices: &mut Int64Builder,
) -> Result<(), AppError> {
    let schema = Schema::new(vec![
        Field::new("term", DataType::Utf8, false),
        Field::new("hash", DataType::Utf8, false),
        Field::new("record_index", DataType::Int64, false),
    ]);
    let batch = RecordBatch::try_new(
        Arc::new(schema),
        vec![
            Arc::new(terms.finish()),
            Arc::new(hashes.finish()),
            Arc::new(indices.finish()),
        ],
    )
    .map_err(storage)?;
    appender.append_record_batch(batch).map_err(storage)
}

fn append_observations(
    tx: &Transaction<'_>,
    hash: &str,
    records: &[Tainted<GraphRecord>],
) -> Result<(), AppError> {
    let mut appender = tx.appender("observations").map_err(storage)?;
    each_record(records, |record| {
        let record_index = index(record)?;
        for (kind, value) in &record.entities {
            appender
                .append_row((
                    hash,
                    record_index,
                    record.at.as_str(),
                    record.event.as_str(),
                    kind.as_str(),
                    value.as_str(),
                ))
                .map_err(storage)?;
        }
        Ok(())
    })?;
    appender.flush().map_err(storage)
}

fn append_relations(
    tx: &Transaction<'_>,
    hash: &str,
    records: &[Tainted<GraphRecord>],
) -> Result<(), AppError> {
    let mut appender = tx.appender("relations").map_err(storage)?;
    each_record(records, |record| {
        let record_index = index(record)?;
        for relation in &record.relations {
            appender
                .append_row((
                    hash,
                    record_index,
                    record.at.as_str(),
                    relation.from_kind.as_str(),
                    relation.from_value.as_str(),
                    relation.relation.as_str(),
                    relation.to_kind.as_str(),
                    relation.to_value.as_str(),
                ))
                .map_err(storage)?;
        }
        Ok(())
    })?;
    appender.flush().map_err(storage)
}
