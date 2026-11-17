use crate::{Error, invalid};
use std::ops::{Add, Mul, Neg, Sub};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Duration(pub(crate) time::SignedDuration);
pub type TimeDelta = Duration;
#[derive(Clone, Copy, Debug)]
pub struct Days(pub(crate) u64);
impl Days {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Months(pub(crate) u32);
impl Months {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
}
impl Duration {
    pub const fn zero() -> Self {
        Self(time::SignedDuration::ZERO)
    }
    pub const fn seconds(v: i32) -> Self {
        Self(time::SignedDuration::seconds(v as i64))
    }
    pub const fn milliseconds(v: i32) -> Self {
        Self(time::SignedDuration::milliseconds(v as i64))
    }
    pub const fn microseconds(v: i64) -> Self {
        Self(time::SignedDuration::microseconds(v))
    }
    pub const fn nanoseconds(v: i64) -> Self {
        Self(time::SignedDuration::nanoseconds(v))
    }
    pub fn minutes(v: i32) -> Self {
        Self(time::SignedDuration::minutes(i64::from(v)))
    }
    pub fn hours(v: i32) -> Self {
        Self(time::SignedDuration::hours(i64::from(v)))
    }
    pub fn days(v: i32) -> Self {
        Self(time::SignedDuration::days(i64::from(v)))
    }
    pub fn weeks(v: i32) -> Self {
        Self(time::SignedDuration::weeks(i64::from(v)))
    }
    pub fn try_seconds(v: i64) -> Option<Self> {
        v.checked_mul(1000)
            .map(|_| Self(time::SignedDuration::seconds(v)))
    }
    pub fn try_milliseconds(v: i64) -> Option<Self> {
        (v != i64::MIN).then(|| Self(time::SignedDuration::milliseconds(v)))
    }
    pub fn try_minutes(v: i64) -> Option<Self> {
        Self::try_seconds(v.checked_mul(60)?)
    }
    pub fn try_hours(v: i64) -> Option<Self> {
        Self::try_seconds(v.checked_mul(3600)?)
    }
    pub fn try_days(v: i64) -> Option<Self> {
        Self::try_seconds(v.checked_mul(86400)?)
    }
    pub fn num_seconds(self) -> i64 {
        self.0.whole_seconds()
    }
    pub fn num_minutes(self) -> i64 {
        self.0.whole_minutes()
    }
    pub fn num_hours(self) -> i64 {
        self.0.whole_hours()
    }
    pub fn num_days(self) -> i64 {
        self.0.whole_days()
    }
    pub fn num_milliseconds(self) -> i64 {
        self.0.whole_seconds() * 1000 + i64::from(self.0.subsec_milliseconds())
    }
    pub fn num_microseconds(self) -> Option<i64> {
        i64::try_from(self.0.whole_microseconds()).ok()
    }
    pub fn num_nanoseconds(self) -> Option<i64> {
        i64::try_from(self.0.whole_nanoseconds()).ok()
    }
    pub fn to_std(self) -> Result<std::time::Duration, Error> {
        self.0.try_into().map_err(|_| invalid())
    }
    pub fn from_std(v: std::time::Duration) -> Result<Self, Error> {
        time::SignedDuration::try_from(v)
            .map(Self)
            .map_err(|_| invalid())
    }
}
impl Add for Duration {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}
impl Sub for Duration {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}
impl Neg for Duration {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}
impl Mul<i32> for Duration {
    type Output = Self;
    fn mul(self, rhs: i32) -> Self {
        Self(self.0 * rhs)
    }
}
impl std::fmt::Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
