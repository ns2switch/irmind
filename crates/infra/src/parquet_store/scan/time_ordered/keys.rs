//! Conservative stable-key bounds for legacy groups tied at whole-second time.
use super::{AppError, ArrowReaderMetadata, BTreeMap, ScanSpec, group_reader, storage};
use crate::parquet_store::{invalid_source, time_cell::TimeCell};
use arrow::array::{Array as _, StringArray, UInt64Array};
use parquet::file::metadata::RowGroupMetaData;
use parquet::file::statistics::Statistics;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    source: String,
    hash: String,
    index: u64,
}

impl Key {
    fn for_hash(
        hash: &str,
        index: u64,
        spec: &ScanSpec<'_>,
        names: &BTreeMap<String, String>,
    ) -> Result<Self, AppError> {
        let artifact = spec.artifacts.first().ok_or_else(invalid_source)?;
        if artifact
            .source_hashes()
            .binary_search_by(|h| h.as_str().cmp(hash))
            .is_err()
        {
            return Err(invalid_source());
        }
        Ok(Self {
            source: names.get(hash).map_or(hash, String::as_str).into(),
            hash: hash.into(),
            index,
        })
    }

    fn cannot_beat(&self, cutoff: &TimeCell) -> bool {
        match (self.source.as_str(), self.hash.as_str())
            .cmp(&(cutoff.source.as_str(), cutoff.hash.as_str()))
        {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal if cutoff.offset.is_none() => self.index > cutoff.index,
            _ => false,
        }
    }
}

pub(super) fn cannot_beat(
    file: &std::fs::File,
    metadata: &ArrowReaderMetadata,
    spec: &ScanSpec<'_>,
    names: &BTreeMap<String, String>,
    group: usize,
    cutoff: &TimeCell,
) -> Result<bool, AppError> {
    let schema = metadata.schema();
    let row_group = metadata.metadata().row_group(group);
    if let Some((hash, index)) = single_source(row_group, schema.as_ref())? {
        return Ok(Key::for_hash(hash, index, spec, names)?.cannot_beat(cutoff));
    }
    // Mixed-source bounds cannot infer name order from hash order. Read only
    // the compact reference columns, never event text or model content.
    let reader = group_reader(file, metadata, &["source_hash", "record_index"], &[], group)?;
    let mut first = None::<Key>;
    for batch in reader {
        if spec.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if std::time::Instant::now() >= spec.deadline {
            return Err(AppError::Policy(
                "Parquet query exceeded 10-second budget".into(),
            ));
        }
        let batch = batch.map_err(storage)?;
        let hashes = batch
            .column_by_name("source_hash")
            .and_then(|a| a.as_any().downcast_ref::<StringArray>());
        let indexes = batch
            .column_by_name("record_index")
            .and_then(|a| a.as_any().downcast_ref::<UInt64Array>());
        let (Some(hashes), Some(indexes)) = (hashes, indexes) else {
            return Err(invalid_source());
        };
        let mut previous = None;
        for row in 0..batch.num_rows() {
            if hashes.is_null(row) || indexes.is_null(row) {
                return Err(invalid_source());
            }
            let hash = hashes.value(row);
            let index = indexes.value(row);
            // Repeated references need no new strings or map lookup.
            if previous.is_some_and(|(h, i)| h == hash && i <= index) {
                continue;
            }
            previous = Some((hash, index));
            let key = Key::for_hash(hash, index, spec, names)?;
            if first.as_ref().is_none_or(|old| key < *old) {
                first = Some(key);
            }
        }
    }
    Ok(first.is_some_and(|key| key.cannot_beat(cutoff)))
}

fn single_source<'a>(
    group: &'a RowGroupMetaData,
    schema: &arrow::datatypes::Schema,
) -> Result<Option<(&'a str, u64)>, AppError> {
    let column = schema.index_of("source_hash").map_err(storage)?;
    let Some(stats) = group.column(column).statistics() else {
        return Ok(None);
    };
    if !stats.min_is_exact() || !stats.max_is_exact() || stats.null_count_opt() != Some(0) {
        return Ok(None);
    }
    let (Some(min), Some(max)) = (stats.min_bytes_opt(), stats.max_bytes_opt()) else {
        return Ok(None);
    };
    if min != max {
        return Ok(None);
    }
    let hash = std::str::from_utf8(min).map_err(|_| invalid_source())?;
    let column = schema.index_of("record_index").map_err(storage)?;
    let index = match group.column(column).statistics() {
        Some(Statistics::Int64(v)) if v.min_is_exact() && v.null_count_opt() == Some(0) => v
            .min_opt()
            .and_then(|v| u64::try_from(*v).ok())
            .unwrap_or(0),
        _ => 0,
    };
    Ok(Some((hash, index)))
}
