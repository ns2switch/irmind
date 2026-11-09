//! Typed time columns are resolved once per batch; every row keeps full validation.
use super::{AppError, RecordBatch, invalid_source};
use arrow::array::{
    Array, BooleanArray, StringArray, TimestampMicrosecondArray, UInt8Array, UInt16Array,
};
use irmind_app::{IndexedInstant, IndexedTime, TimePrecision};

pub(super) enum TimeColumns<'a> {
    Precise {
        values: &'a TimestampMicrosecondArray,
        residual: &'a UInt16Array,
        precision: &'a UInt8Array,
        inferred: &'a BooleanArray,
    },
    Legacy(&'a StringArray),
}

pub(super) fn column<'a, T: Array + 'static>(batch: &'a RecordBatch, name: &str) -> Option<&'a T> {
    batch.column_by_name(name)?.as_any().downcast_ref()
}

impl<'a> TimeColumns<'a> {
    pub(super) fn new(batch: &'a RecordBatch) -> Result<Self, AppError> {
        if let Some(values) = batch
            .column_by_name("_irmind_instant")
            .or_else(|| batch.column_by_name("event_time"))
            .and_then(|a| a.as_any().downcast_ref::<TimestampMicrosecondArray>())
        {
            return Ok(Self::Precise {
                values,
                residual: column(batch, "submicro_nanos").ok_or_else(invalid_source)?,
                precision: column(batch, "time_precision").ok_or_else(invalid_source)?,
                inferred: column(batch, "time_inferred").ok_or_else(invalid_source)?,
            });
        }
        column(batch, "event_time")
            .map(Self::Legacy)
            .ok_or_else(invalid_source)
    }

    pub(super) fn at(&self, row: usize) -> Result<Option<IndexedTime>, AppError> {
        match self {
            Self::Precise {
                values,
                residual,
                precision,
                inferred,
            } => {
                if precision.is_null(row) || inferred.is_null(row) {
                    return Err(invalid_source());
                }
                if values.is_null(row) {
                    if !residual.is_null(row) || precision.value(row) != 0 || inferred.value(row) {
                        return Err(invalid_source());
                    }
                    return Ok(None);
                }
                if residual.is_null(row) {
                    return Err(invalid_source());
                }
                let instant = IndexedInstant::new(values.value(row), residual.value(row))
                    .map_err(|_| invalid_source())?;
                let precision =
                    TimePrecision::from_code(precision.value(row)).map_err(|_| invalid_source())?;
                IndexedTime::new(instant, precision, inferred.value(row))
                    .map(Some)
                    .map_err(|_| invalid_source())
            }
            Self::Legacy(values) => legacy(values.value(row)),
        }
    }
}

fn legacy(raw: &str) -> Result<Option<IndexedTime>, AppError> {
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

#[cfg(test)]
mod tests;
