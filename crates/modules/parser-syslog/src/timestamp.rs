use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use irmind_app::AppError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyTimestamp {
    year: i32,
    offset_minutes: i32,
}

impl LegacyTimestamp {
    pub fn new(year: i32, offset_minutes: i32) -> Result<Self, AppError> {
        if !(1..=9999).contains(&year) || !(-1439..=1439).contains(&offset_minutes) {
            return Err(super::invalid());
        }
        Ok(Self {
            year,
            offset_minutes,
        })
    }
    #[must_use]
    pub fn year(self) -> i32 {
        self.year
    }
    #[must_use]
    pub fn offset_minutes(self) -> i32 {
        self.offset_minutes
    }
    pub(super) fn parse(self, raw: &str) -> Result<String, AppError> {
        let input = format!("{} {raw}", self.year);
        let naive = NaiveDateTime::parse_from_str(&input, "%Y %b %e %H:%M:%S")
            .map_err(|_| super::invalid())?;
        let at = FixedOffset::east_opt(self.offset_minutes * 60)
            .ok_or_else(super::invalid)?
            .from_local_datetime(&naive)
            .single()
            .ok_or_else(super::invalid)?;
        Ok(at
            .with_timezone(&Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    }
}

pub(super) fn explicit(raw: &str) -> Result<String, AppError> {
    let at = DateTime::parse_from_rfc3339(raw)
        .map_err(|_| AppError::Policy("invalid RFC 5424 timestamp".into()))?;
    if at.timestamp_subsec_nanos() >= 1_000_000_000 {
        return Err(super::invalid());
    }
    Ok(at
        .with_timezone(&Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
}
