use crate::{
    Datelike, Days, Duration, Error, Months, NaiveDate, NaiveDateTime, NaiveTime, SecondsFormat,
    Timelike, Weekday, format, invalid,
};
use std::{
    cmp::Ordering,
    marker::PhantomData,
    ops::{Add, Sub},
};
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Utc;
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FixedOffset(pub(crate) time::UtcOffset);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalResult<T> {
    None,
    Single(T),
    Ambiguous(T, T),
}
impl<T> LocalResult<T> {
    pub fn single(self) -> Option<T> {
        if let Self::Single(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn earliest(self) -> Option<T> {
        match self {
            Self::Single(v) | Self::Ambiguous(v, _) => Some(v),
            Self::None => None,
        }
    }
    pub fn latest(self) -> Option<T> {
        match self {
            Self::Single(v) | Self::Ambiguous(_, v) => Some(v),
            Self::None => None,
        }
    }
    pub fn map<U>(self, f: impl Fn(T) -> U) -> LocalResult<U> {
        match self {
            Self::None => LocalResult::None,
            Self::Single(v) => LocalResult::Single(f(v)),
            Self::Ambiguous(a, b) => LocalResult::Ambiguous(f(a), f(b)),
        }
    }
}
pub trait Offset: std::fmt::Display + Clone {
    fn fix(&self) -> FixedOffset;
}
#[allow(clippy::wrong_self_convention)] // Matches the reviewed fixed-offset consumer API.
pub trait TimeZone: Sized + Clone {
    type Offset: Offset;
    fn from_offset(value: &Self::Offset) -> Self;
    fn offset_from_local_date(&self, local: &NaiveDate) -> LocalResult<Self::Offset>;
    fn offset_from_local_datetime(&self, local: &NaiveDateTime) -> LocalResult<Self::Offset>;
    fn offset_from_utc_date(&self, utc: &NaiveDate) -> Self::Offset;
    fn offset_from_utc_datetime(&self, utc: &NaiveDateTime) -> Self::Offset;
    fn from_utc_datetime(&self, utc: &NaiveDateTime) -> DateTime<Self> {
        DateTime::from_naive_utc_and_offset(*utc, self.offset_from_utc_datetime(utc))
    }
    fn from_local_datetime(&self, local: &NaiveDateTime) -> LocalResult<DateTime<Self>> {
        self.offset_from_local_datetime(local).map(|offset| {
            let mut utc = *local - Duration::seconds(offset.fix().local_minus_utc());
            utc.time.leap = local.time.leap;
            DateTime::from_naive_utc_and_offset(utc, offset)
        })
    }
    fn with_ymd_and_hms(
        &self,
        y: i32,
        m: u32,
        d: u32,
        h: u32,
        min: u32,
        s: u32,
    ) -> LocalResult<DateTime<Self>> {
        match NaiveDate::from_ymd_opt(y, m, d).and_then(|d| d.and_hms_opt(h, min, s)) {
            Some(v) => self.from_local_datetime(&v),
            None => LocalResult::None,
        }
    }
    fn timestamp_opt(&self, s: i64, ns: u32) -> LocalResult<DateTime<Self>> {
        DateTime::<Utc>::from_timestamp(s, ns).map_or(LocalResult::None, |v| {
            LocalResult::Single(v.with_timezone(self))
        })
    }
    fn timestamp_millis_opt(&self, ms: i64) -> LocalResult<DateTime<Self>> {
        self.timestamp_opt(
            ms.div_euclid(1000),
            match u32::try_from(ms.rem_euclid(1000)) {
                Ok(v) => v,
                Err(_) => return LocalResult::None,
            } * 1_000_000,
        )
    }
    fn timestamp_nanos(&self, ns: i64) -> DateTime<Self> {
        DateTime::<Utc>::from_timestamp_nanos(ns).with_timezone(self)
    }
}
impl FixedOffset {
    pub fn east_opt(seconds: i32) -> Option<Self> {
        time::UtcOffset::from_whole_seconds(seconds).ok().map(Self)
    }
    pub fn west_opt(seconds: i32) -> Option<Self> {
        Self::east_opt(seconds.checked_neg()?)
    }
    pub fn local_minus_utc(self) -> i32 {
        self.0.whole_seconds()
    }
    pub fn utc_minus_local(self) -> i32 {
        -self.local_minus_utc()
    }
}
impl std::str::FromStr for FixedOffset {
    type Err = Error;
    fn from_str(raw: &str) -> Result<Self, Error> {
        if matches!(raw, "Z" | "UTC" | "+00:00" | "-00:00") {
            return Ok(Self(time::UtcOffset::UTC));
        }
        if !raw.is_ascii() || !(3..=9).contains(&raw.len()) {
            return Err(invalid());
        }
        let sign = match raw.as_bytes()[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return Err(invalid()),
        };
        let numbers = raw[1..].replace(':', "");
        if ![2, 4, 6].contains(&numbers.len()) || !numbers.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let h = numbers[..2].parse::<i32>().map_err(|_| invalid())?;
        let m = if numbers.len() >= 4 {
            numbers[2..4].parse::<i32>().map_err(|_| invalid())?
        } else {
            0
        };
        let s = if numbers.len() == 6 {
            numbers[4..6].parse::<i32>().map_err(|_| invalid())?
        } else {
            0
        };
        if h > 23 || m > 59 || s > 59 {
            return Err(invalid());
        }
        Self::east_opt(sign * (h * 3600 + m * 60 + s)).ok_or_else(invalid)
    }
}
impl std::fmt::Display for FixedOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.local_minus_utc();
        write!(
            f,
            "{}{:02}:{:02}",
            if s < 0 { "-" } else { "+" },
            s.abs() / 3600,
            s.abs() / 60 % 60
        )?;
        if s % 60 != 0 {
            write!(f, ":{:02}", s.abs() % 60)?;
        }
        Ok(())
    }
}
impl std::fmt::Display for Utc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UTC")
    }
}
impl Offset for Utc {
    fn fix(&self) -> FixedOffset {
        FixedOffset(time::UtcOffset::UTC)
    }
}
impl Offset for FixedOffset {
    fn fix(&self) -> Self {
        *self
    }
}
impl TimeZone for Utc {
    type Offset = Utc;
    fn from_offset(_: &Utc) -> Self {
        Utc
    }
    fn offset_from_local_date(&self, _: &NaiveDate) -> LocalResult<Utc> {
        LocalResult::Single(Utc)
    }
    fn offset_from_local_datetime(&self, _: &NaiveDateTime) -> LocalResult<Utc> {
        LocalResult::Single(Utc)
    }
    fn offset_from_utc_date(&self, _: &NaiveDate) -> Utc {
        Utc
    }
    fn offset_from_utc_datetime(&self, _: &NaiveDateTime) -> Utc {
        Utc
    }
}
impl TimeZone for FixedOffset {
    type Offset = Self;
    fn from_offset(value: &Self) -> Self {
        *value
    }
    fn offset_from_local_date(&self, _: &NaiveDate) -> LocalResult<Self> {
        LocalResult::Single(*self)
    }
    fn offset_from_local_datetime(&self, _: &NaiveDateTime) -> LocalResult<Self> {
        LocalResult::Single(*self)
    }
    fn offset_from_utc_date(&self, _: &NaiveDate) -> Self {
        *self
    }
    fn offset_from_utc_datetime(&self, _: &NaiveDateTime) -> Self {
        *self
    }
}
#[derive(Clone)]
pub struct DateTime<Tz: TimeZone> {
    utc: NaiveDateTime,
    offset: Tz::Offset,
    marker: PhantomData<Tz>,
}
impl<T: TimeZone> Copy for DateTime<T> where T::Offset: Copy {}
impl<T: TimeZone> DateTime<T> {
    pub fn from_naive_utc_and_offset(utc: NaiveDateTime, offset: T::Offset) -> Self {
        Self {
            utc,
            offset,
            marker: PhantomData,
        }
    }
    pub fn with_timezone<Z: TimeZone>(&self, tz: &Z) -> DateTime<Z> {
        tz.from_utc_datetime(&self.utc)
    }
    pub fn naive_utc(&self) -> NaiveDateTime {
        self.utc
    }
    pub fn naive_local(&self) -> NaiveDateTime {
        {
            let mut local = self.utc + Duration::seconds(self.offset.fix().local_minus_utc());
            local.time.leap = self.utc.time.leap;
            local
        }
    }
    pub fn date_naive(&self) -> NaiveDate {
        self.naive_local().date()
    }
    pub fn time(&self) -> NaiveTime {
        self.naive_local().time()
    }
    pub fn offset(&self) -> &T::Offset {
        &self.offset
    }
    pub fn timezone(&self) -> T {
        T::from_offset(&self.offset)
    }
    pub fn timestamp(&self) -> i64 {
        self.utc.native().assume_utc().unix_timestamp()
    }
    pub fn timestamp_subsec_nanos(&self) -> u32 {
        self.utc.nanosecond()
    }
    pub fn timestamp_subsec_micros(&self) -> u32 {
        self.timestamp_subsec_nanos() / 1000
    }
    pub fn timestamp_subsec_millis(&self) -> u32 {
        self.timestamp_subsec_nanos() / 1_000_000
    }
    pub fn timestamp_millis(&self) -> i64 {
        self.timestamp() * 1000 + i64::from(self.timestamp_subsec_millis())
    }
    pub fn timestamp_micros(&self) -> i64 {
        self.timestamp() * 1_000_000 + i64::from(self.timestamp_subsec_micros())
    }
    pub fn timestamp_nanos_opt(&self) -> Option<i64> {
        self.timestamp()
            .checked_mul(1_000_000_000)?
            .checked_add(i64::from(self.timestamp_subsec_nanos()))
    }
    #[allow(clippy::needless_pass_by_value)] // Same by-value API as vendored temporal kernels.
    pub fn signed_duration_since<Z: TimeZone>(&self, other: DateTime<Z>) -> Duration {
        self.utc.signed_duration_since(other.utc)
    }
    pub fn checked_add_signed(self, d: Duration) -> Option<Self> {
        Some(Self::from_naive_utc_and_offset(
            self.utc.checked_add_signed(d)?,
            self.offset,
        ))
    }
    pub fn checked_sub_signed(self, d: Duration) -> Option<Self> {
        Some(Self::from_naive_utc_and_offset(
            self.utc.checked_sub_signed(d)?,
            self.offset,
        ))
    }
    pub fn checked_add_days(self, d: Days) -> Option<Self> {
        let tz = self.timezone();
        tz.from_local_datetime(&self.naive_local().checked_add_days(d)?)
            .single()
    }
    pub fn checked_sub_days(self, d: Days) -> Option<Self> {
        let tz = self.timezone();
        tz.from_local_datetime(&self.naive_local().checked_sub_days(d)?)
            .single()
    }
    pub fn checked_add_months(self, d: Months) -> Option<Self> {
        let tz = self.timezone();
        tz.from_local_datetime(&self.naive_local().checked_add_months(d)?)
            .single()
    }
    pub fn checked_sub_months(self, d: Months) -> Option<Self> {
        let tz = self.timezone();
        tz.from_local_datetime(&self.naive_local().checked_sub_months(d)?)
            .single()
    }
    pub fn format(&self, fmt: &str) -> crate::Formatted {
        format::zoned(
            self.naive_local(),
            self.offset.fix(),
            &self.offset.to_string(),
            fmt,
        )
    }
    pub fn to_rfc3339(&self) -> String {
        self.to_rfc3339_opts(SecondsFormat::AutoSi, false)
    }
    pub fn to_rfc3339_opts(&self, precision: SecondsFormat, z: bool) -> String {
        let local = self.naive_local();
        let date = local.date();
        let clock = format::clock_text(local.time(), precision);
        format!(
            "{date}T{clock}{}",
            if z && self.offset.fix().local_minus_utc() == 0 {
                "Z".into()
            } else {
                self.offset.fix().to_string()
            }
        )
    }
}
impl DateTime<Utc> {
    pub fn from_timestamp(s: i64, ns: u32) -> Option<Self> {
        if ns >= 2_000_000_000 || ns >= 1_000_000_000 && s.rem_euclid(60) != 59 {
            return None;
        }
        let at = time::OffsetDateTime::from_unix_timestamp(s)
            .ok()?
            .replace_nanosecond(ns % 1_000_000_000)
            .ok()?;
        let mut value =
            NaiveDateTime::from_native(time::PrimitiveDateTime::new(at.date(), at.time()))?;
        value.time.leap = ns >= 1_000_000_000;
        Some(Self::from_naive_utc_and_offset(value, Utc))
    }
    pub fn from_timestamp_millis(v: i64) -> Option<Self> {
        Self::from_timestamp(
            v.div_euclid(1000),
            u32::try_from(v.rem_euclid(1000)).ok()? * 1_000_000,
        )
    }
    pub fn from_timestamp_micros(v: i64) -> Option<Self> {
        Self::from_timestamp(
            v.div_euclid(1_000_000),
            u32::try_from(v.rem_euclid(1_000_000)).ok()? * 1000,
        )
    }
    pub fn from_timestamp_nanos(v: i64) -> Self {
        let n = time::OffsetDateTime::UNIX_EPOCH + time::SignedDuration::nanoseconds(v);
        Self::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate(n.date()),
                NaiveTime {
                    value: n.time(),
                    leap: false,
                },
            ),
            Utc,
        )
    }
}
impl Utc {
    pub fn now() -> DateTime<Utc> {
        std::time::SystemTime::now().into()
    }
}
impl From<std::time::SystemTime> for DateTime<Utc> {
    fn from(v: std::time::SystemTime) -> Self {
        let at: time::OffsetDateTime = v.into();
        Self::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate(at.date()),
                NaiveTime {
                    value: at.time(),
                    leap: false,
                },
            ),
            Utc,
        )
    }
}
impl From<DateTime<Utc>> for std::time::SystemTime {
    fn from(v: DateTime<Utc>) -> Self {
        v.utc.native().assume_utc().into()
    }
}
impl DateTime<FixedOffset> {
    pub fn parse_from_str(raw: &str, fmt: &str) -> Result<Self, Error> {
        let (local, offset) = format::parse_offset(raw, fmt)?;
        offset
            .from_local_datetime(&local)
            .single()
            .ok_or_else(invalid)
    }
    pub fn parse_from_rfc3339(raw: &str) -> Result<Self, Error> {
        if !raw.is_ascii() || raw.len() < 20 || raw.len() > 64 {
            return Err(invalid());
        }
        let mut s = raw.to_owned();
        if matches!(s.as_bytes()[10], b't' | b' ') {
            s.replace_range(10..11, "T");
        }
        if s.ends_with(['Z', 'z']) {
            s.pop();
            s.push_str("+00:00");
        }
        Self::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.f%:z")
    }
    pub fn parse_from_rfc2822(raw: &str) -> Result<Self, Error> {
        let at = time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc2822)
            .map_err(|e| Error(e.to_string()))?;
        let local = NaiveDateTime::from_native(time::PrimitiveDateTime::new(at.date(), at.time()))
            .ok_or_else(invalid)?;
        FixedOffset(at.offset())
            .from_local_datetime(&local)
            .single()
            .ok_or_else(invalid)
    }
}
impl<T: TimeZone, Z: TimeZone> PartialEq<DateTime<Z>> for DateTime<T> {
    fn eq(&self, rhs: &DateTime<Z>) -> bool {
        self.utc == rhs.utc
    }
}
impl<T: TimeZone> Eq for DateTime<T> {}
impl<T: TimeZone, Z: TimeZone> PartialOrd<DateTime<Z>> for DateTime<T> {
    fn partial_cmp(&self, rhs: &DateTime<Z>) -> Option<Ordering> {
        Some(self.utc.cmp(&rhs.utc))
    }
}
impl<T: TimeZone> Ord for DateTime<T> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.utc.cmp(&rhs.utc)
    }
}
impl<T: TimeZone> std::fmt::Display for DateTime<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.naive_local(), self.offset)
    }
}
impl<T: TimeZone> std::fmt::Debug for DateTime<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    }
}
impl<T: TimeZone> Datelike for DateTime<T> {
    fn year(&self) -> i32 {
        self.naive_local().year()
    }
    fn month(&self) -> u32 {
        self.naive_local().month()
    }
    fn day(&self) -> u32 {
        self.naive_local().day()
    }
    fn ordinal(&self) -> u32 {
        self.naive_local().ordinal()
    }
    fn weekday(&self) -> Weekday {
        self.naive_local().weekday()
    }
    fn num_days_from_ce(&self) -> i32 {
        self.naive_local().num_days_from_ce()
    }
}
impl<T: TimeZone> Timelike for DateTime<T> {
    fn hour(&self) -> u32 {
        self.naive_local().hour()
    }
    fn minute(&self) -> u32 {
        self.naive_local().minute()
    }
    fn second(&self) -> u32 {
        self.naive_local().second()
    }
    fn nanosecond(&self) -> u32 {
        self.utc.nanosecond()
    }
}
impl<T: TimeZone> Add<Duration> for DateTime<T> {
    type Output = Self;
    fn add(self, d: Duration) -> Self {
        Self::from_naive_utc_and_offset(self.utc + d, self.offset)
    }
}
impl<T: TimeZone> Sub<Duration> for DateTime<T> {
    type Output = Self;
    fn sub(self, d: Duration) -> Self {
        self + (-d)
    }
}
impl<T: TimeZone, Z: TimeZone> Sub<DateTime<Z>> for DateTime<T> {
    type Output = Duration;
    fn sub(self, d: DateTime<Z>) -> Duration {
        self.utc - d.utc
    }
}
impl<T: TimeZone> Add<std::time::Duration> for DateTime<T> {
    type Output = Self;
    fn add(self, d: std::time::Duration) -> Self {
        let utc = self.utc.native() + d;
        Self::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate(utc.date()),
                NaiveTime {
                    value: utc.time(),
                    leap: false,
                },
            ),
            self.offset,
        )
    }
}
impl<T: TimeZone> serde::Serialize for DateTime<T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    }
}
impl<'de> serde::Deserialize<'de> for DateTime<Utc> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|v| v.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

impl Default for FixedOffset {
    fn default() -> Self {
        Self(time::UtcOffset::UTC)
    }
}
impl std::fmt::Debug for FixedOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
