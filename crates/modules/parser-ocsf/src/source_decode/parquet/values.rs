//! Decode Parquet primitives into source values without a JSON tree round trip.
use crate::source_decode::invalid;
use ::parquet::record::{Field, Row};
use irmind_app::AppError;
use irmind_domain::{
    SOURCE_MAX_BYTES, SOURCE_MAX_DEPTH, SOURCE_MAX_NODES, SourceNumber, SourceValue,
};
#[derive(Default)]
struct Budget {
    nodes: usize,
    fields: usize,
    bytes: usize,
}
impl Budget {
    fn node(&mut self, depth: usize) -> Result<(), AppError> {
        self.nodes += 1;
        if depth > SOURCE_MAX_DEPTH || self.nodes > SOURCE_MAX_NODES {
            return Err(invalid());
        }
        Ok(())
    }
    fn bytes(&mut self, size: usize) -> Result<(), AppError> {
        self.bytes = self.bytes.checked_add(size).ok_or_else(invalid)?;
        if self.bytes > SOURCE_MAX_BYTES {
            return Err(invalid());
        }
        Ok(())
    }
    fn key(&mut self, key: &str) -> Result<(), AppError> {
        self.fields += 1;
        if self.fields > 1024 {
            return Err(invalid());
        }
        self.bytes(key.len())
    }
}
pub(super) fn decode(row: &Row) -> Result<SourceValue, AppError> {
    object(row, 0, &mut Budget::default())
}
fn object(row: &Row, depth: usize, budget: &mut Budget) -> Result<SourceValue, AppError> {
    budget.node(depth)?;
    let mut fields = Vec::new();
    for (key, field) in row.get_column_iter() {
        budget.key(key)?;
        fields.push((key.clone(), value(field, depth + 1, budget)?));
    }
    SourceValue::object(fields).map_err(|_| invalid())
}
fn value(field: &Field, depth: usize, budget: &mut Budget) -> Result<SourceValue, AppError> {
    if let Field::Group(row) = field {
        return object(row, depth, budget);
    }
    budget.node(depth)?;
    match field {
        Field::Null => Ok(SourceValue::Null),
        Field::Bool(value) => Ok(SourceValue::Boolean(*value)),
        Field::Byte(v) => number(&v.to_string()),
        Field::Short(v) => number(&v.to_string()),
        Field::Int(v) => number(&v.to_string()),
        Field::Long(v) => number(&v.to_string()),
        Field::UByte(v) => number(&v.to_string()),
        Field::UShort(v) => number(&v.to_string()),
        Field::UInt(v) => number(&v.to_string()),
        Field::ULong(v) => number(&v.to_string()),
        Field::Float16(v) => number(&f64::from(*v).to_string()),
        Field::Float(v) => number(&f64::from(*v).to_string()),
        Field::Double(v) => number(&v.to_string()),
        Field::Decimal(_) => number(&field.to_string()),
        Field::Str(value) => {
            budget.bytes(value.len())?;
            Ok(SourceValue::Text(value.clone()))
        }
        Field::Bytes(value) => {
            budget.bytes(value.len())?;
            Ok(SourceValue::Bytes(value.data().to_vec()))
        }
        Field::Date(_)
        | Field::TimeMillis(_)
        | Field::TimeMicros(_)
        | Field::TimestampMillis(_)
        | Field::TimestampMicros(_) => {
            let text = temporal(field)?;
            budget.bytes(text.len())?;
            Ok(SourceValue::Text(text))
        }
        Field::ListInternal(values) => {
            let mut items = Vec::new();
            for field in values.elements() {
                items.push(value(field, depth + 1, budget)?);
            }
            Ok(SourceValue::Array(items))
        }
        Field::MapInternal(map) => {
            let mut fields = Vec::new();
            for (key, field) in map.entries() {
                let Field::Str(key) = key else {
                    return Err(invalid());
                };
                budget.key(key)?;
                fields.push((key.clone(), value(field, depth + 1, budget)?));
            }
            SourceValue::object(fields).map_err(|_| invalid())
        }
        Field::Group(_) => Err(invalid()),
    }
}
fn temporal(field: &Field) -> Result<String, AppError> {
    use chrono::{DateTime, NaiveDate, NaiveTime, SecondsFormat, TimeDelta};
    match field {
        Field::Date(days) => NaiveDate::from_ymd_opt(1970, 1, 1)
            .and_then(|d| d.checked_add_signed(TimeDelta::days(i64::from(*days))))
            .map(|d| d.to_string())
            .ok_or_else(invalid),
        Field::TimeMillis(value) => {
            let value = u32::try_from(*value).map_err(|_| invalid())?;
            NaiveTime::from_num_seconds_from_midnight_opt(value / 1000, value % 1000 * 1_000_000)
                .map(|v| v.format("%H:%M:%S%.3f").to_string())
                .ok_or_else(invalid)
        }
        Field::TimeMicros(value) => {
            let value = u64::try_from(*value).map_err(|_| invalid())?;
            let seconds = u32::try_from(value / 1_000_000).map_err(|_| invalid())?;
            NaiveTime::from_num_seconds_from_midnight_opt(
                seconds,
                u32::try_from(value % 1_000_000 * 1000).map_err(|_| invalid())?,
            )
            .map(|v| v.format("%H:%M:%S%.6f").to_string())
            .ok_or_else(invalid)
        }
        Field::TimestampMillis(value) => DateTime::from_timestamp_millis(*value)
            .map(|v| v.to_rfc3339_opts(SecondsFormat::Millis, true))
            .ok_or_else(invalid),
        Field::TimestampMicros(value) => DateTime::from_timestamp_micros(*value)
            .map(|v| v.to_rfc3339_opts(SecondsFormat::Micros, true))
            .ok_or_else(invalid),
        _ => Err(invalid()),
    }
}
fn number(value: &str) -> Result<SourceValue, AppError> {
    SourceNumber::try_new(value)
        .map(SourceValue::Number)
        .map_err(|_| invalid())
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn binary_is_binary_and_nonfinite_values_are_rejected() {
        let row = ::parquet::record::Row::new(vec![(
            "bytes".into(),
            Field::Bytes(vec![0, 255, 10].into()),
        )]);
        assert_eq!(
            decode(&row).unwrap().field("bytes"),
            Some(&SourceValue::Bytes(vec![0, 255, 10]))
        );
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let row = ::parquet::record::Row::new(vec![("n".into(), Field::Double(value))]);
            assert!(decode(&row).is_err());
        }
    }
}
