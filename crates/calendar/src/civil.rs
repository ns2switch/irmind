use crate::{DateTime, Datelike, Days, Duration, Error, Months, Timelike, Utc, format};
use std::ops::{Add, Sub};
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NaiveDate(pub(crate) time::Date);
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct NaiveTime {
    pub(crate) value: time::Time,
    pub(crate) leap: bool,
}
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NaiveDateTime {
    pub(crate) date: NaiveDate,
    pub(crate) time: NaiveTime,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Weekday(time::Weekday);
impl Weekday {
    pub fn num_days_from_sunday(self) -> u32 {
        u32::from(self.0.number_days_from_sunday())
    }
    pub fn num_days_from_monday(self) -> u32 {
        u32::from(self.0.number_days_from_monday())
    }
    pub fn number_from_sunday(self) -> u32 {
        self.num_days_from_sunday() + 1
    }
    pub fn number_from_monday(self) -> u32 {
        self.num_days_from_monday() + 1
    }
}
impl NaiveDate {
    pub const MIN: Self = Self(
        match time::Date::from_calendar_date(-262_143, time::Month::January, 1) {
            Ok(v) => v,
            Err(_) => time::OffsetDateTime::UNIX_EPOCH.date(),
        },
    );
    pub const MAX: Self = Self(
        match time::Date::from_calendar_date(262_142, time::Month::December, 31) {
            Ok(v) => v,
            Err(_) => time::OffsetDateTime::UNIX_EPOCH.date(),
        },
    );
    pub fn from_ymd_opt(year: i32, month: u32, day: u32) -> Option<Self> {
        if !(-262_143..=262_142).contains(&year) {
            return None;
        }
        let month = time::Month::try_from(u8::try_from(month).ok()?).ok()?;
        time::Date::from_calendar_date(year, month, u8::try_from(day).ok()?)
            .ok()
            .map(Self)
    }
    pub fn from_num_days_from_ce_opt(days: i32) -> Option<Self> {
        let julian = days.checked_add(1_721_425)?;
        let date = Self(time::Date::from_julian_day(julian).ok()?);
        (date >= Self::MIN && date <= Self::MAX).then_some(date)
    }
    pub fn parse_from_str(raw: &str, fmt: &str) -> Result<Self, Error> {
        format::parse_date(raw, fmt)
    }
    pub const fn and_time(self, time: NaiveTime) -> NaiveDateTime {
        NaiveDateTime { date: self, time }
    }
    pub fn and_hms_opt(self, h: u32, m: u32, s: u32) -> Option<NaiveDateTime> {
        Some(self.and_time(NaiveTime::from_hms_opt(h, m, s)?))
    }
    pub fn and_hms_milli_opt(self, h: u32, m: u32, s: u32, ms: u32) -> Option<NaiveDateTime> {
        Some(self.and_time(NaiveTime::from_hms_milli_opt(h, m, s, ms)?))
    }
    pub fn and_hms_micro_opt(self, h: u32, m: u32, s: u32, us: u32) -> Option<NaiveDateTime> {
        Some(self.and_time(NaiveTime::from_hms_micro_opt(h, m, s, us)?))
    }
    pub fn and_hms_nano_opt(self, h: u32, m: u32, s: u32, ns: u32) -> Option<NaiveDateTime> {
        Some(self.and_time(NaiveTime::from_hms_nano_opt(h, m, s, ns)?))
    }
    pub fn checked_add_signed(self, d: Duration) -> Option<Self> {
        let v = Self(self.0.checked_add(d.0)?);
        (v >= Self::MIN && v <= Self::MAX).then_some(v)
    }
    pub fn checked_sub_signed(self, d: Duration) -> Option<Self> {
        self.checked_add_signed(-d)
    }
    pub fn checked_add_days(self, d: Days) -> Option<Self> {
        self.checked_add_signed(Duration::try_days(i64::try_from(d.0).ok()?)?)
    }
    pub fn checked_sub_days(self, d: Days) -> Option<Self> {
        self.checked_sub_signed(Duration::try_days(i64::try_from(d.0).ok()?)?)
    }
    pub fn checked_add_months(self, m: Months) -> Option<Self> {
        self.add_months(i64::from(m.0))
    }
    pub fn checked_sub_months(self, m: Months) -> Option<Self> {
        self.add_months(-i64::from(m.0))
    }
    fn add_months(self, n: i64) -> Option<Self> {
        let total = i64::from(self.year())
            .checked_mul(12)?
            .checked_add(i64::from(self.month()) - 1)?
            .checked_add(n)?;
        let year = i32::try_from(total.div_euclid(12)).ok()?;
        let month = u32::try_from(total.rem_euclid(12) + 1).ok()?;
        (28..=self.day())
            .rev()
            .find_map(|day| Self::from_ymd_opt(year, month, day))
            .or_else(|| Self::from_ymd_opt(year, month, self.day()))
    }
    pub fn signed_duration_since(self, other: Self) -> Duration {
        Duration(self.0 - other.0)
    }
    pub fn format(&self, fmt: &str) -> crate::Formatted {
        format::date(*self, fmt)
    }
    pub fn with_year(self, year: i32) -> Option<Self> {
        Self::from_ymd_opt(year, self.month(), self.day())
    }
    pub fn with_month(self, month: u32) -> Option<Self> {
        Self::from_ymd_opt(self.year(), month, self.day())
    }
    pub fn with_day(self, day: u32) -> Option<Self> {
        Self::from_ymd_opt(self.year(), self.month(), day)
    }
}
impl Default for NaiveDate {
    fn default() -> Self {
        Self(time::OffsetDateTime::UNIX_EPOCH.date())
    }
}
impl Datelike for NaiveDate {
    fn year(&self) -> i32 {
        self.0.year()
    }
    fn month(&self) -> u32 {
        u32::from(self.0.month() as u8)
    }
    fn day(&self) -> u32 {
        u32::from(self.0.day())
    }
    fn ordinal(&self) -> u32 {
        u32::from(self.0.ordinal())
    }
    fn weekday(&self) -> Weekday {
        Weekday(self.0.weekday())
    }
    fn num_days_from_ce(&self) -> i32 {
        self.0.to_julian_day() - 1_721_425
    }
}
impl NaiveTime {
    pub fn from_hms_opt(h: u32, m: u32, s: u32) -> Option<Self> {
        Self::from_hms_nano_opt(h, m, s, 0)
    }
    pub fn from_hms_milli_opt(h: u32, m: u32, s: u32, ms: u32) -> Option<Self> {
        Self::from_hms_nano_opt(h, m, s, ms.checked_mul(1_000_000)?)
    }
    pub fn from_hms_micro_opt(h: u32, m: u32, s: u32, us: u32) -> Option<Self> {
        Self::from_hms_nano_opt(h, m, s, us.checked_mul(1000)?)
    }
    pub fn from_hms_nano_opt(h: u32, m: u32, s: u32, ns: u32) -> Option<Self> {
        if ns >= 2_000_000_000 || ns >= 1_000_000_000 && s != 59 {
            return None;
        }
        Some(Self {
            value: time::Time::from_hms_nano(
                u8::try_from(h).ok()?,
                u8::try_from(m).ok()?,
                u8::try_from(s).ok()?,
                ns % 1_000_000_000,
            )
            .ok()?,
            leap: ns >= 1_000_000_000,
        })
    }
    pub fn from_num_seconds_from_midnight_opt(s: u32, ns: u32) -> Option<Self> {
        if s >= 86400 {
            return None;
        }
        Self::from_hms_nano_opt(s / 3600, s / 60 % 60, s % 60, ns)
    }
    pub fn parse_from_str(raw: &str, fmt: &str) -> Result<Self, Error> {
        format::parse_time(raw, fmt)
    }
    pub fn format(&self, fmt: &str) -> crate::Formatted {
        format::clock(*self, fmt)
    }
}
impl Default for NaiveTime {
    fn default() -> Self {
        Self {
            value: time::Time::MIDNIGHT,
            leap: false,
        }
    }
}
impl Timelike for NaiveTime {
    fn hour(&self) -> u32 {
        u32::from(self.value.hour())
    }
    fn minute(&self) -> u32 {
        u32::from(self.value.minute())
    }
    fn second(&self) -> u32 {
        u32::from(self.value.second())
    }
    fn nanosecond(&self) -> u32 {
        self.value.nanosecond() + if self.leap { 1_000_000_000 } else { 0 }
    }
}
impl NaiveDateTime {
    pub const fn new(date: NaiveDate, time: NaiveTime) -> Self {
        Self { date, time }
    }
    pub fn parse_from_str(raw: &str, fmt: &str) -> Result<Self, Error> {
        format::parse_naive(raw, fmt)
    }
    pub const fn date(self) -> NaiveDate {
        self.date
    }
    pub const fn time(self) -> NaiveTime {
        self.time
    }
    pub fn and_utc(self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(self, Utc)
    }
    #[allow(clippy::needless_pass_by_value)] // Same timezone construction API as reviewed consumers.
    pub fn and_local_timezone<T: crate::TimeZone>(self, tz: T) -> crate::LocalResult<DateTime<T>> {
        tz.from_local_datetime(&self)
    }
    pub fn native(self) -> time::PrimitiveDateTime {
        time::PrimitiveDateTime::new(self.date.0, self.time.value)
    }
    pub(crate) fn from_native(v: time::PrimitiveDateTime) -> Option<Self> {
        let d = NaiveDate(v.date());
        (d >= NaiveDate::MIN && d <= NaiveDate::MAX).then_some(Self::new(
            d,
            NaiveTime {
                value: v.time(),
                leap: false,
            },
        ))
    }
    pub fn checked_add_signed(self, d: Duration) -> Option<Self> {
        Self::from_native(self.native().checked_add(d.0)?)
    }
    pub fn checked_sub_signed(self, d: Duration) -> Option<Self> {
        Self::from_native(self.native().checked_sub(d.0)?)
    }
    pub fn checked_add_months(self, m: Months) -> Option<Self> {
        Some(Self::new(self.date.checked_add_months(m)?, self.time))
    }
    pub fn checked_sub_months(self, m: Months) -> Option<Self> {
        Some(Self::new(self.date.checked_sub_months(m)?, self.time))
    }
    pub fn checked_add_days(self, d: Days) -> Option<Self> {
        Some(Self::new(self.date.checked_add_days(d)?, self.time))
    }
    pub fn checked_sub_days(self, d: Days) -> Option<Self> {
        Some(Self::new(self.date.checked_sub_days(d)?, self.time))
    }
    pub fn signed_duration_since(self, other: Self) -> Duration {
        Duration(self.native() - other.native())
    }
    pub fn format(&self, fmt: &str) -> crate::Formatted {
        format::naive(*self, fmt)
    }
    pub fn with_nanosecond(self, n: u32) -> Option<Self> {
        Some(Self::new(
            self.date,
            NaiveTime::from_hms_nano_opt(self.hour(), self.minute(), self.second(), n)?,
        ))
    }
}
impl Default for NaiveDateTime {
    fn default() -> Self {
        Self::new(NaiveDate::default(), NaiveTime::default())
    }
}
impl Datelike for NaiveDateTime {
    fn year(&self) -> i32 {
        self.date.year()
    }
    fn month(&self) -> u32 {
        self.date.month()
    }
    fn day(&self) -> u32 {
        self.date.day()
    }
    fn ordinal(&self) -> u32 {
        self.date.ordinal()
    }
    fn weekday(&self) -> Weekday {
        self.date.weekday()
    }
    fn num_days_from_ce(&self) -> i32 {
        self.date.num_days_from_ce()
    }
}
impl Timelike for NaiveDateTime {
    fn hour(&self) -> u32 {
        self.time.hour()
    }
    fn minute(&self) -> u32 {
        self.time.minute()
    }
    fn second(&self) -> u32 {
        self.time.second()
    }
    fn nanosecond(&self) -> u32 {
        self.time.nanosecond()
    }
}
impl Add<Duration> for NaiveDate {
    type Output = Self;
    fn add(self, d: Duration) -> Self {
        Self(self.0 + d.0)
    }
}
impl Sub<NaiveDate> for NaiveDate {
    type Output = Duration;
    fn sub(self, rhs: Self) -> Duration {
        self.signed_duration_since(rhs)
    }
}
impl Add<Duration> for NaiveDateTime {
    type Output = Self;
    fn add(self, d: Duration) -> Self {
        let n = self.native() + d.0;
        Self::new(
            NaiveDate(n.date()),
            NaiveTime {
                value: n.time(),
                leap: false,
            },
        )
    }
}
impl Sub<Duration> for NaiveDateTime {
    type Output = Self;
    fn sub(self, d: Duration) -> Self {
        self + (-d)
    }
}
impl Sub<NaiveDateTime> for NaiveDateTime {
    type Output = Duration;
    fn sub(self, d: Self) -> Duration {
        self.signed_duration_since(d)
    }
}
impl std::fmt::Display for NaiveDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format::date_text(self.year(), self.month(), self.day()))
    }
}
impl std::fmt::Display for NaiveTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format::clock_text(*self, crate::SecondsFormat::AutoSi))
    }
}
impl std::fmt::Display for NaiveDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.date, self.time)
    }
}

// Invalid backend bounds fail at compile time, rather than substituting another date.
const _: [(); 1] = [(); (NaiveDate::MIN.0.year() == -262_143) as usize];
const _: [(); 1] = [(); (NaiveDate::MAX.0.year() == 262_142) as usize];
impl Ord for NaiveTime {
    fn cmp(&self, rhs: &Self) -> std::cmp::Ordering {
        (self.hour(), self.minute(), self.second(), self.nanosecond()).cmp(&(
            rhs.hour(),
            rhs.minute(),
            rhs.second(),
            rhs.nanosecond(),
        ))
    }
}
impl PartialOrd for NaiveTime {
    fn partial_cmp(&self, rhs: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}
impl std::fmt::Debug for NaiveDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::fmt::Debug for NaiveTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::fmt::Debug for NaiveDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}T{}", self.date, self.time)
    }
}

impl Sub<crate::FixedOffset> for NaiveDateTime {
    type Output = Self;
    fn sub(self, o: crate::FixedOffset) -> Self {
        let mut v = self - Duration::seconds(o.local_minus_utc());
        v.time.leap = self.time.leap;
        v
    }
}
impl Add<crate::FixedOffset> for NaiveDateTime {
    type Output = Self;
    fn add(self, o: crate::FixedOffset) -> Self {
        let mut v = self + Duration::seconds(o.local_minus_utc());
        v.time.leap = self.time.leap;
        v
    }
}
