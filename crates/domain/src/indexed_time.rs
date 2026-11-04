mod calendar;
mod order;
mod parse;
pub use order::{StableRecordKey, compare_record_keys};

use crate::DomainError;

/// UTC time for the new derived schema; existing signed timestamps stay unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct IndexedInstant {
    micros: i64,
    submicro_nanos: u16,
}

impl IndexedInstant {
    pub const MIN_MICROS: i64 = -62_135_596_800_000_000;
    pub const MAX_MICROS: i64 = 253_402_300_799_999_999;

    pub fn new(micros: i64, submicro_nanos: u16) -> Result<Self, DomainError> {
        if !(Self::MIN_MICROS..=Self::MAX_MICROS).contains(&micros) || submicro_nanos > 999 {
            return Err(DomainError::InvalidTimestamp);
        }
        Ok(Self {
            micros,
            submicro_nanos,
        })
    }

    pub const fn unix_micros(self) -> i64 {
        self.micros
    }
    pub const fn submicro_nanos(self) -> u16 {
        self.submicro_nanos
    }

    pub fn utc_date(self) -> String {
        calendar::date(self)
    }
}

/// Stable physical enum codes for the new Parquet schema, independent of display text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TimePrecision {
    Unknown = 0,
    Second = 1,
    Millisecond = 2,
    Microsecond = 3,
    Nanosecond = 4,
}

impl TimePrecision {
    pub fn from_code(code: u8) -> Result<Self, DomainError> {
        match code {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Second),
            2 => Ok(Self::Millisecond),
            3 => Ok(Self::Microsecond),
            4 => Ok(Self::Nanosecond),
            _ => Err(DomainError::InvalidTimestamp),
        }
    }

    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Second => "second",
            Self::Millisecond => "millisecond",
            Self::Microsecond => "microsecond",
            Self::Nanosecond => "nanosecond",
        }
    }
}

/// Precision and inference describe the source, rather than claiming a measured microsecond.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexedTime {
    instant: IndexedInstant,
    precision: TimePrecision,
    inferred: bool,
}

impl IndexedTime {
    pub fn new(
        instant: IndexedInstant,
        precision: TimePrecision,
        inferred: bool,
    ) -> Result<Self, DomainError> {
        let aligned = match precision {
            TimePrecision::Second => {
                instant.micros.rem_euclid(1_000_000) == 0 && instant.submicro_nanos == 0
            }
            TimePrecision::Millisecond => {
                instant.micros.rem_euclid(1000) == 0 && instant.submicro_nanos == 0
            }
            TimePrecision::Microsecond => instant.submicro_nanos == 0,
            TimePrecision::Nanosecond | TimePrecision::Unknown => true,
        };
        if !aligned {
            return Err(DomainError::InvalidTimestamp);
        }
        Ok(Self {
            instant,
            precision,
            inferred,
        })
    }

    pub fn from_rfc3339(value: &str, inferred: bool) -> Result<Self, DomainError> {
        parse::rfc3339(value, inferred)
    }

    pub fn from_epoch_decimal(value: &str, inferred: bool) -> Result<Self, DomainError> {
        parse::epoch_decimal(value, inferred)
    }

    pub const fn instant(self) -> IndexedInstant {
        self.instant
    }
    pub const fn precision(self) -> TimePrecision {
        self.precision
    }
    pub const fn inferred(self) -> bool {
        self.inferred
    }

    /// UTC with the precision marker available separately for coarse/inferred labels.
    pub fn to_rfc3339(self) -> String {
        calendar::format(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
