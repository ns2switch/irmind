use super::{AppError, RecordBatch, invalid_source};
use arrow::array::{
    Array, BooleanArray, StringArray, TimestampMicrosecondArray, UInt8Array, UInt16Array,
    UInt64Array,
};
use irmind_app::{IndexedInstant, IndexedTime, TimePrecision};

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
        let time = read_time(batch, row)?;
        let hash = super::query::text(batch, "source_hash", row)?.to_owned();
        let source = batch
            .column_by_name("_irmind_source")
            .and_then(|a| a.as_any().downcast_ref::<StringArray>())
            .map_or(hash.as_str(), |a| a.value(row))
            .to_owned();
        let offset = batch
            .column_by_name("source_offset")
            .and_then(|a| a.as_any().downcast_ref::<UInt64Array>())
            .and_then(|a| (!a.is_null(row)).then(|| a.value(row)));
        Ok(Self {
            time,
            source,
            hash,
            offset,
            index: super::query::number(batch, "record_index", row)?,
        })
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
    if let Some(physical) = batch
        .column_by_name("_irmind_instant")
        .or_else(|| batch.column_by_name("event_time"))
        .and_then(|a| a.as_any().downcast_ref::<TimestampMicrosecondArray>())
    {
        let residual = batch
            .column_by_name("submicro_nanos")
            .and_then(|a| a.as_any().downcast_ref::<UInt16Array>())
            .ok_or_else(invalid_source)?;
        let precision = batch
            .column_by_name("time_precision")
            .and_then(|a| a.as_any().downcast_ref::<UInt8Array>())
            .ok_or_else(invalid_source)?;
        let inferred = batch
            .column_by_name("time_inferred")
            .and_then(|a| a.as_any().downcast_ref::<BooleanArray>())
            .ok_or_else(invalid_source)?;
        if precision.is_null(row) || inferred.is_null(row) {
            return Err(invalid_source());
        }
        if physical.is_null(row) {
            if !residual.is_null(row) || precision.value(row) != 0 || inferred.value(row) {
                return Err(invalid_source());
            }
            return Ok(None);
        }
        if residual.is_null(row) {
            return Err(invalid_source());
        }
        let instant = IndexedInstant::new(physical.value(row), residual.value(row))
            .map_err(|_| invalid_source())?;
        let precision =
            TimePrecision::from_code(precision.value(row)).map_err(|_| invalid_source())?;
        return IndexedTime::new(instant, precision, inferred.value(row))
            .map(Some)
            .map_err(|_| invalid_source());
    }
    let raw = super::query::text(batch, "event_time", row)?;
    if raw.is_empty() {
        return Ok(None);
    }
    let seconds = irmind_domain::UtcTimestamp::parse(raw)
        .map_err(|_| invalid_source())?
        .unix_seconds();
    let instant = IndexedInstant::new(
        seconds.checked_mul(1_000_000).ok_or_else(invalid_source)?,
        0,
    )
    .map_err(|_| invalid_source())?;
    IndexedTime::new(instant, TimePrecision::Second, false)
        .map(Some)
        .map_err(|_| invalid_source())
}

/// A source uses one stable-order unit even when observations span batches/files.
pub(super) fn validate_source_units(
    batch: &RecordBatch,
    modes: &mut std::collections::BTreeMap<String, bool>,
) -> Result<(), AppError> {
    let offsets = batch
        .column_by_name("source_offset")
        .and_then(|a| a.as_any().downcast_ref::<UInt64Array>());
    for row in 0..batch.num_rows() {
        let hash = super::query::text(batch, "source_hash", row)?;
        let has_offset = offsets.is_some_and(|a| !a.is_null(row));
        if modes.get(hash).is_some_and(|old| *old != has_offset) {
            return Err(invalid_source());
        }
        modes.insert(hash.into(), has_offset);
    }
    Ok(())
}
