use super::{AppError, GraphRecord, Tainted, Transaction, storage, terms};
use crate::graph_duckdb::profile::{GraphInsertProfile, GraphPhase, measure};
use irmind_app::CancellationToken;

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
    let mut rows = 0usize;
    each_record(records, |record| {
        let record_index = index(record)?;
        for term in terms(&record.text)? {
            if rows.is_multiple_of(8_192) && cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            appender
                .append_row((term.as_str(), hash, record_index))
                .map_err(storage)?;
            rows += 1;
        }
        Ok(())
    })?;
    appender.flush().map_err(storage)
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
