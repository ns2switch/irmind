//! Batch-lifetime ordering keys; allocate only retained extrema or output rows.
use super::{AppError, RecordBatch, TimeCell, invalid_source, read_time};
use arrow::array::{Array as _, StringArray, UInt64Array};
use irmind_app::IndexedTime;

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
        let time = read_time(batch, row)?;
        let hash = super::super::query::text(batch, "source_hash", row)?;
        let source = batch
            .column_by_name("_irmind_source")
            .and_then(|a| a.as_any().downcast_ref::<StringArray>())
            .map_or(hash, |a| a.value(row));
        let offset = batch
            .column_by_name("source_offset")
            .and_then(|a| a.as_any().downcast_ref::<UInt64Array>())
            .and_then(|a| (!a.is_null(row)).then(|| a.value(row)));
        Ok(Self {
            time,
            source,
            hash,
            offset,
            index: super::super::query::number(batch, "record_index", row)?,
        })
    }

    pub(in crate::parquet_store) fn has_time(&self) -> bool {
        self.time.is_some()
    }

    pub(in crate::parquet_store) fn compare(
        &self,
        other: &TimeCell,
        newest: bool,
    ) -> Result<std::cmp::Ordering, AppError> {
        irmind_domain::compare_record_keys(
            irmind_domain::StableRecordKey {
                instant: self.time.map(IndexedTime::instant),
                source: self.source,
                source_hash: self.hash,
                source_offset: self.offset,
                record_index: self.index,
            },
            other.key(),
            newest,
        )
        .map_err(|_| invalid_source())
    }

    pub(in crate::parquet_store) fn to_owned(&self) -> TimeCell {
        TimeCell {
            time: self.time,
            source: self.source.into(),
            hash: self.hash.into(),
            offset: self.offset,
            index: self.index,
        }
    }
}
