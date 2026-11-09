//! Batch-lifetime ordering keys; allocate only retained extrema or output rows.
use super::columns::{TimeColumns, column};
use super::{AppError, RecordBatch, TimeCell, invalid_source};
use arrow::array::{Array as _, StringArray, UInt64Array};
use irmind_app::IndexedTime;

#[derive(Clone, Copy)]
pub(in crate::parquet_store) struct BorrowedCell<'a> {
    time: Option<IndexedTime>,
    source: &'a str,
    hash: &'a str,
    offset: Option<u64>,
    index: u64,
}

impl<'a> BorrowedCell<'a> {
    pub(in crate::parquet_store) fn from_batch(
        batch: &'a RecordBatch,
        row: usize,
    ) -> Result<Self, AppError> {
        BorrowedRows::new(batch)?.at(row)
    }

    pub(in crate::parquet_store) fn has_time(&self) -> bool {
        self.time.is_some()
    }

    pub(in crate::parquet_store) fn compare(
        &self,
        other: &TimeCell,
        newest: bool,
    ) -> Result<std::cmp::Ordering, AppError> {
        irmind_domain::compare_record_keys(self.key(), other.key(), newest)
            .map_err(|_| invalid_source())
    }

    pub(in crate::parquet_store) fn compare_borrowed(
        self,
        other: Self,
    ) -> Result<std::cmp::Ordering, AppError> {
        irmind_domain::compare_record_keys(self.key(), other.key(), false)
            .map_err(|_| invalid_source())
    }

    fn key(self) -> irmind_domain::StableRecordKey<'a> {
        irmind_domain::StableRecordKey {
            instant: self.time.map(IndexedTime::instant),
            source: self.source,
            source_hash: self.hash,
            source_offset: self.offset,
            record_index: self.index,
        }
    }

    pub(in crate::parquet_store) fn to_owned(self) -> TimeCell {
        TimeCell {
            time: self.time,
            source: self.source.into(),
            hash: self.hash.into(),
            offset: self.offset,
            index: self.index,
        }
    }
}

/// Borrowed, checked column bindings for count/extrema aggregation.
pub(in crate::parquet_store) struct BorrowedRows<'a> {
    time: TimeColumns<'a>,
    hashes: &'a StringArray,
    sources: Option<&'a StringArray>,
    offsets: Option<&'a UInt64Array>,
    indexes: &'a UInt64Array,
}
impl<'a> BorrowedRows<'a> {
    pub(in crate::parquet_store) fn new(batch: &'a RecordBatch) -> Result<Self, AppError> {
        Ok(Self {
            time: TimeColumns::new(batch)?,
            hashes: column(batch, "source_hash").ok_or_else(invalid_source)?,
            sources: column(batch, "_irmind_source"),
            offsets: column(batch, "source_offset"),
            indexes: column(batch, "record_index").ok_or_else(invalid_source)?,
        })
    }
    pub(in crate::parquet_store) fn at(&self, row: usize) -> Result<BorrowedCell<'a>, AppError> {
        let hash = self.hashes.value(row);
        Ok(BorrowedCell {
            time: self.time.at(row)?,
            source: self.sources.map_or(hash, |a| a.value(row)),
            hash,
            offset: self
                .offsets
                .and_then(|a| (!a.is_null(row)).then(|| a.value(row))),
            index: self.indexes.value(row),
        })
    }
}
