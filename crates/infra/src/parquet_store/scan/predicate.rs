use super::RecordBatch;
mod numeric;
use arrow::{
    array::{Array, StringArray, UInt64Array},
    error::ArrowError,
};
use memchr::{memchr, memchr2};
#[derive(Clone)]
pub(in crate::parquet_store) enum Predicate {
    Equal(&'static str, String),
    Mask(&'static str, u32, u32),
    SmallEqual(&'static str, Option<u16>, u8),
    Range(&'static str, String, String),
    ContainsIgnoreCase(&'static str, String),
    Index(u64),
    TimeRange(irmind_app::IndexedInstant, irmind_app::IndexedInstant),
}

impl Predicate {
    pub(super) fn may_match_numeric_statistics(
        &self,
        stats: &parquet::file::statistics::Statistics,
    ) -> bool {
        numeric::may_match_statistics(self, stats)
    }

    pub(super) fn column(&self) -> &'static str {
        match self {
            Self::Mask(column, _, _)
            | Self::SmallEqual(column, _, _)
            | Self::Equal(column, _)
            | Self::Range(column, _, _)
            | Self::ContainsIgnoreCase(column, _) => column,
            Self::Index(_) => "record_index",
            Self::TimeRange(..) => "event_time",
        }
    }

    pub(super) fn matches(&self, batch: &RecordBatch, row: usize) -> Result<bool, ArrowError> {
        let column = batch
            .column_by_name(self.column())
            .ok_or_else(|| ArrowError::SchemaError("missing Parquet predicate column".into()))?;
        if matches!(self, Self::Mask(..) | Self::SmallEqual(..)) {
            return numeric::matches(self, column.as_ref(), row);
        }
        if let Self::TimeRange(from, to) = self {
            if let Some(times) = column.as_any().downcast_ref::<StringArray>() {
                if times.is_null(row) || times.value(row).is_empty() {
                    return Ok(false);
                }
                let instant = irmind_app::IndexedTime::from_rfc3339(times.value(row), false)
                    .map_err(|_| ArrowError::SchemaError("invalid legacy time".into()))?
                    .instant();
                return Ok(instant >= *from && instant <= *to);
            }
            let times = column
                .as_any()
                .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
                .ok_or_else(|| ArrowError::SchemaError("invalid time column".into()))?;
            let residual = batch
                .column_by_name("submicro_nanos")
                .and_then(|a| a.as_any().downcast_ref::<arrow::array::UInt16Array>())
                .ok_or_else(|| ArrowError::SchemaError("missing residual time".into()))?;
            if times.is_null(row) || residual.is_null(row) {
                return Ok(false);
            }
            let instant = irmind_app::IndexedInstant::new(times.value(row), residual.value(row))
                .map_err(|_| ArrowError::SchemaError("invalid time value".into()))?;
            return Ok(instant >= *from && instant <= *to);
        }
        if let Self::Index(index) = self {
            let values = column
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| {
                    ArrowError::SchemaError("invalid Parquet record index column".into())
                })?;
            Ok(!values.is_null(row) && values.value(row) == *index)
        } else {
            let values = column
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| ArrowError::SchemaError("invalid Parquet text column".into()))?;
            if values.is_null(row) {
                return Ok(false);
            }
            let value = values.value(row);
            Ok(match self {
                Self::Equal(_, expected) => value == expected,
                Self::Range(_, first, last) => value >= first.as_str() && value <= last.as_str(),
                Self::ContainsIgnoreCase(_, needle) => contains_ignore_case(value, needle),
                Self::Index(_) | Self::TimeRange(..) | Self::Mask(..) | Self::SmallEqual(..) => {
                    false
                }
            })
        }
    }
}

pub(super) fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_ascii() {
        let bytes = haystack.as_bytes();
        let target = needle.as_bytes();
        if target.is_empty() {
            return true;
        }
        if target.len() > bytes.len() {
            return false;
        }
        let last = target[target.len() - 1];
        let mut offset = target.len() - 1;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            let found = if last.is_ascii_alphabetic() {
                memchr2(
                    last.to_ascii_lowercase(),
                    last.to_ascii_uppercase(),
                    remaining,
                )
            } else {
                memchr(last, remaining)
            };
            let Some(found) = found else { break };
            let end = offset + found + 1;
            if bytes[end - target.len()..end].eq_ignore_ascii_case(target) {
                return true;
            }
            offset = end;
        }
        return false;
    }
    haystack.to_lowercase().contains(&needle.to_lowercase())
}
