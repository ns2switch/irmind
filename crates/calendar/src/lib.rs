#![forbid(unsafe_code)]
//! Portable calendar values backed by `time`, shared by the reviewed date consumers.
//! This facade carries subsecond and fixed-offset semantics; it never reads a timezone database.
mod civil;
mod duration;
mod format;
mod zone;
pub use civil::{NaiveDate, NaiveDateTime, NaiveTime, Weekday};
pub use duration::{Days, Duration, Months, TimeDelta};
pub use format::{Formatted, SecondsFormat, has_timezone, validate_format};
pub use time;
pub use zone::{DateTime, FixedOffset, LocalResult, Offset, TimeZone, Utc};
pub type ParseError = Error;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
pub(crate) fn invalid() -> Error {
    Error("invalid or out-of-range calendar value".into())
}
pub mod offset {
    pub use crate::{LocalResult, Offset, TimeZone, Utc};
}
pub mod naive {
    pub use crate::{NaiveDate, NaiveDateTime, NaiveTime};
}
pub mod prelude {
    pub use crate::{
        DateTime, Datelike, FixedOffset, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, Offset,
        TimeZone, Timelike, Utc,
    };
}
pub trait Datelike {
    fn year(&self) -> i32;
    fn month(&self) -> u32;
    fn day(&self) -> u32;
    fn ordinal(&self) -> u32;
    fn weekday(&self) -> Weekday;
    fn quarter(&self) -> u32 {
        (self.month() - 1) / 3 + 1
    }
    fn num_days_from_ce(&self) -> i32;
}
pub trait Timelike {
    fn hour(&self) -> u32;
    fn minute(&self) -> u32;
    fn second(&self) -> u32;
    fn nanosecond(&self) -> u32;
    fn num_seconds_from_midnight(&self) -> u32 {
        self.hour() * 3600 + self.minute() * 60 + self.second()
    }
}

#[cfg(test)]
mod tests;

#[cfg(feature = "config-duration")]
mod config_duration;
#[cfg(feature = "config-duration")]
pub use config_duration::parse_config_duration;
