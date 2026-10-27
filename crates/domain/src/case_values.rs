use crate::{DomainError, IocType};
use std::net::IpAddr;

/// An exact UTC instant in the existing fixed-width signed timestamp format.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct UtcTimestamp {
    unix_seconds: i64,
    text: String,
}

impl UtcTimestamp {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let bytes = value.as_bytes();
        if bytes.len() != 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'Z'
            || bytes.iter().enumerate().any(|(index, byte)| {
                !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
            })
        {
            return Err(DomainError::InvalidTimestamp);
        }
        let number = |start: usize, end: usize| -> Result<u32, DomainError> {
            value[start..end]
                .parse::<u32>()
                .map_err(|_| DomainError::InvalidTimestamp)
        };
        let year = number(0, 4)?;
        let month = number(5, 7)?;
        let day = number(8, 10)?;
        let hour = number(11, 13)?;
        let minute = number(14, 16)?;
        let second = number(17, 19)?;
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let max_day = match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            _ => 0,
        };
        if year == 0 || !(1..=max_day).contains(&day) || hour > 23 || minute > 59 || second > 59 {
            return Err(DomainError::InvalidTimestamp);
        }
        // Civil date to days since Unix epoch; valid for the entire four-digit year range.
        let adjusted_year = i64::from(year) - i64::from(month <= 2);
        let era = adjusted_year.div_euclid(400);
        let year_of_era = adjusted_year - era * 400;
        let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
        let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
        let year_of_era_days =
            year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + year_of_era_days - 719_468;
        Ok(Self {
            unix_seconds: days * 86_400
                + i64::from(hour) * 3_600
                + i64::from(minute) * 60
                + i64::from(second),
            text: value.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub const fn unix_seconds(&self) -> i64 {
        self.unix_seconds
    }
}

/// A SHA-256 evidence address. The signed wire form remains lowercase hex.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EvidenceHash(String);

impl EvidenceHash {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DomainError::InvalidEvidenceHash);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An IOC value validated for its declared kind before it enters the domain model.
#[derive(Clone, Eq, PartialEq)]
pub struct IocValue {
    kind: IocType,
    value: String,
}

impl std::fmt::Debug for IocValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IocValue")
            .field("kind", &self.kind)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl IocValue {
    pub fn parse(kind: IocType, value: &str) -> Result<Self, DomainError> {
        let valid = match kind {
            IocType::Ip => value.parse::<IpAddr>().is_ok(),
            IocType::Domain => valid_domain(value),
            IocType::Hash => {
                matches!(value.len(), 32 | 40 | 64 | 128)
                    && value.bytes().all(|b| b.is_ascii_hexdigit())
            }
            IocType::User => valid_identifier(value, 1, 128, b"._@\\/-:"),
            IocType::Key => valid_identifier(value, 8, 128, b"/_+=-"),
        };
        if !valid {
            return Err(DomainError::InvalidIocValue);
        }
        Ok(Self {
            kind,
            value: value.to_owned(),
        })
    }

    pub fn kind(&self) -> IocType {
        self.kind
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

fn valid_identifier(value: &str, min: usize, max: usize, extra: &[u8]) -> bool {
    (min..=max).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
}

fn valid_domain(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_a_real_instant_and_rejects_impossible_dates() {
        let leap = UtcTimestamp::parse("2024-02-29T23:59:59Z").unwrap();
        let next = UtcTimestamp::parse("2024-03-01T00:00:00Z").unwrap();
        assert_eq!(next.unix_seconds() - leap.unix_seconds(), 1);
        for invalid in [
            "2026-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00+00:00",
        ] {
            assert!(UtcTimestamp::parse(invalid).is_err());
        }
    }

    #[test]
    fn hash_and_ioc_values_reject_invalid_forms() {
        assert!(EvidenceHash::parse(&"a".repeat(64)).is_ok());
        assert!(EvidenceHash::parse(&"A".repeat(64)).is_err());
        assert!(EvidenceHash::parse(&"a".repeat(63)).is_err());
        for (kind, good, bad) in [
            (IocType::Ip, "2001:db8::1", "999.2.3.4"),
            (IocType::Domain, "example.org", "-bad.example"),
            (IocType::Hash, "a2345678901234567890123456789012", "not-hex"),
            (IocType::User, "analyst@example.org", "bad user"),
            (IocType::Key, "AKIA0123456789ABCD12", "bad key"),
        ] {
            assert!(IocValue::parse(kind, good).is_ok());
            assert!(IocValue::parse(kind, bad).is_err());
        }
        assert!(IocValue::parse(IocType::Ip, "203.0.113.8").is_ok());
        assert!(IocValue::parse(IocType::Domain, "203.0.113.8").is_err());
        assert!(
            !format!(
                "{:?}",
                IocValue::parse(IocType::Key, "AKIA0123456789ABCD12").unwrap()
            )
            .contains("AKIA")
        );
    }
}
