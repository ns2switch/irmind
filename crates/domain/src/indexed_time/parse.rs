use super::{DomainError, IndexedInstant, IndexedTime, TimePrecision};
use crate::UtcTimestamp;

fn invalid<T>() -> Result<T, DomainError> {
    Err(DomainError::InvalidTimestamp)
}

fn fraction(value: &str) -> Result<(i128, TimePrecision), DomainError> {
    if value.is_empty() || value.len() > 9 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return invalid();
    }
    let digits = u32::try_from(value.len()).map_err(|_| DomainError::InvalidTimestamp)?;
    let number: i128 = value.parse().map_err(|_| DomainError::InvalidTimestamp)?;
    let precision = match digits {
        1..=3 => TimePrecision::Millisecond,
        4..=6 => TimePrecision::Microsecond,
        _ => TimePrecision::Nanosecond,
    };
    Ok((number * 10_i128.pow(9 - digits), precision))
}

fn from_nanos(
    nanos: i128,
    precision: TimePrecision,
    inferred: bool,
) -> Result<IndexedTime, DomainError> {
    let micros =
        i64::try_from(nanos.div_euclid(1000)).map_err(|_| DomainError::InvalidTimestamp)?;
    let residual =
        u16::try_from(nanos.rem_euclid(1000)).map_err(|_| DomainError::InvalidTimestamp)?;
    IndexedTime::new(IndexedInstant::new(micros, residual)?, precision, inferred)
}

pub(super) fn epoch_decimal(value: &str, inferred: bool) -> Result<IndexedTime, DomainError> {
    if value.len() > 32 || !value.is_ascii() {
        return invalid();
    }
    let (negative, magnitude) = value
        .strip_prefix('-')
        .map_or((false, value), |v| (true, v));
    let (whole, decimal) = magnitude
        .split_once('.')
        .map_or((magnitude, None), |(w, d)| (w, Some(d)));
    if whole.is_empty() || whole.len() > 12 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return invalid();
    }
    let seconds: i128 = whole.parse().map_err(|_| DomainError::InvalidTimestamp)?;
    let (nanos, precision) = decimal.map_or(Ok((0, TimePrecision::Second)), fraction)?;
    // The bounded decimal parser never passes an epoch value through a float.
    let magnitude = seconds
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .ok_or(DomainError::InvalidTimestamp)?;
    from_nanos(
        if negative { -magnitude } else { magnitude },
        precision,
        inferred,
    )
}

pub(super) fn rfc3339(value: &str, inferred: bool) -> Result<IndexedTime, DomainError> {
    if !value.is_ascii() || !(20..=35).contains(&value.len()) {
        return invalid();
    }
    let (clock, offset) = timezone(value)?;
    if clock.len() < 19 {
        return invalid();
    }
    let seconds = UtcTimestamp::parse(&format!("{}Z", &clock[..19]))?.unix_seconds();
    let (nanos, precision) = if clock.len() == 19 {
        (0, TimePrecision::Second)
    } else {
        fraction(
            clock[19..]
                .strip_prefix('.')
                .ok_or(DomainError::InvalidTimestamp)?,
        )?
    };
    let utc = i128::from(seconds)
        .checked_sub(i128::from(offset))
        .and_then(|v| v.checked_mul(1_000_000_000))
        .and_then(|v| v.checked_add(nanos))
        .ok_or(DomainError::InvalidTimestamp)?;
    from_nanos(utc, precision, inferred)
}

fn timezone(value: &str) -> Result<(&str, i64), DomainError> {
    if let Some(clock) = value.strip_suffix('Z') {
        return Ok((clock, 0));
    }
    let split = value
        .len()
        .checked_sub(6)
        .ok_or(DomainError::InvalidTimestamp)?;
    let zone = &value[split..];
    let bytes = zone.as_bytes();
    if !matches!(bytes[0], b'+' | b'-') || bytes[3] != b':' || zone == "-00:00" {
        return invalid();
    }
    if ![bytes[1], bytes[2], bytes[4], bytes[5]]
        .iter()
        .all(u8::is_ascii_digit)
    {
        return invalid();
    }
    let hour: i64 = zone[1..3]
        .parse()
        .map_err(|_| DomainError::InvalidTimestamp)?;
    let minute: i64 = zone[4..6]
        .parse()
        .map_err(|_| DomainError::InvalidTimestamp)?;
    if hour > 23 || minute > 59 {
        return invalid();
    }
    let seconds = hour * 3600 + minute * 60;
    Ok((
        &value[..split],
        if bytes[0] == b'-' { -seconds } else { seconds },
    ))
}
