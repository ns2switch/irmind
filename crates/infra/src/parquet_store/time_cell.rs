use super::{AppError, RecordBatch, invalid_source};
use arrow::array::{Array, StringArray, UInt64Array};
use irmind_app::IndexedTime;
mod borrowed;
mod columns;
pub(super) use borrowed::{BorrowedCell, BorrowedRows};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TimeCell {
    pub time: Option<IndexedTime>,
    pub source: String,
    pub hash: String,
    pub offset: Option<u64>,
    pub index: u64,
}

impl TimeCell {
    pub(super) fn from_batch(batch: &RecordBatch, row: usize) -> Result<Self, AppError> {
        Ok(BorrowedCell::from_batch(batch, row)?.to_owned())
    }
    fn key(&self) -> irmind_domain::StableRecordKey<'_> {
        irmind_domain::StableRecordKey {
            instant: self.time.map(IndexedTime::instant),
            source: &self.source,
            source_hash: &self.hash,
            source_offset: self.offset,
            record_index: self.index,
        }
    }
    pub(super) fn compare(
        &self,
        other: &Self,
        newest: bool,
    ) -> Result<std::cmp::Ordering, AppError> {
        irmind_domain::compare_record_keys(self.key(), other.key(), newest)
            .map_err(|_| invalid_source())
    }
    pub(super) fn display(&self) -> String {
        self.time.map_or_else(String::new, IndexedTime::to_rfc3339)
    }
    pub(super) fn note(&self) -> String {
        self.time.map_or_else(
            || "unknown time".into(),
            |t| {
                format!(
                    "{} precision{}",
                    t.precision().as_str(),
                    if t.inferred() { "; inferred" } else { "" }
                )
            },
        )
    }
}

pub(super) fn read_time(batch: &RecordBatch, row: usize) -> Result<Option<IndexedTime>, AppError> {
    columns::TimeColumns::new(batch)?.at(row)
}

/// Preserve whole-batch time validation when a query does not need display strings.
pub(super) fn validate_times(batch: &RecordBatch) -> Result<(), AppError> {
    let time = columns::TimeColumns::new(batch)?;
    for row in 0..batch.num_rows() {
        time.at(row)?;
    }
    Ok(())
}

/// A source uses one stable-order unit even when observations span batches/files.
pub(super) fn validate_source_units(
    batch: &RecordBatch,
    modes: &mut std::collections::BTreeMap<String, bool>,
) -> Result<(), AppError> {
    let offsets = batch
        .column_by_name("source_offset")
        .and_then(|a| a.as_any().downcast_ref::<UInt64Array>());
    let hashes = batch
        .column_by_name("source_hash")
        .and_then(|a| a.as_any().downcast_ref::<StringArray>())
        .ok_or_else(invalid_source)?;
    let mut previous = None;
    for row in 0..batch.num_rows() {
        let hash = hashes.value(row);
        let has_offset = offsets.is_some_and(|a| !a.is_null(row));
        if previous == Some((hash, has_offset)) {
            continue;
        }

        match modes.get(hash) {
            Some(old) if *old != has_offset => return Err(invalid_source()),
            None => {
                modes.insert(hash.into(), has_offset);
            }
            Some(_) => {}
        }
        previous = Some((hash, has_offset));
    }
    Ok(())
}
