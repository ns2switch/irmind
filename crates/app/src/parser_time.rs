use crate::{AppError, Tainted};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParserTimeBasis {
    Analyst,
    Command,
    ConfirmedSuggestion,
}

impl ParserTimeBasis {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analyst => "analyst",
            Self::Command => "command",
            Self::ConfirmedSuggestion => "confirmed-suggestion",
        }
    }
    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "analyst" => Ok(Self::Analyst),
            "command" => Ok(Self::Command),
            "confirmed-suggestion" => Ok(Self::ConfirmedSuggestion),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserTimeContext {
    year: u16,
    offset_minutes: i16,
    rollover: bool,
    basis: ParserTimeBasis,
}

impl ParserTimeContext {
    pub fn new(
        year: u16,
        offset_minutes: i16,
        rollover: bool,
        basis: ParserTimeBasis,
    ) -> Result<Self, AppError> {
        if !(1..=9999).contains(&year) || !(-1439..=1439).contains(&offset_minutes) {
            return Err(invalid());
        }
        Ok(Self {
            year,
            offset_minutes,
            rollover,
            basis,
        })
    }
    pub fn from_fields(
        year: &str,
        offset: &str,
        rollover: bool,
        basis: ParserTimeBasis,
    ) -> Result<Self, AppError> {
        if year.len() != 4 || !year.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        Self::new(
            year.parse().map_err(|_| invalid())?,
            parse_offset(offset)?,
            rollover,
            basis,
        )
    }
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }
    #[must_use]
    pub const fn offset_minutes(self) -> i16 {
        self.offset_minutes
    }
    #[must_use]
    pub const fn rollover(self) -> bool {
        self.rollover
    }
    #[must_use]
    pub const fn basis(self) -> ParserTimeBasis {
        self.basis
    }
    #[must_use]
    pub fn offset_text(self) -> String {
        let offset = i32::from(self.offset_minutes);
        format!(
            "{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            offset.abs() / 60,
            offset.abs() % 60
        )
    }
}

pub fn parse_offset(value: &str) -> Result<i16, AppError> {
    let bytes = value.as_bytes();
    if bytes.len() != 6
        || !matches!(bytes[0], b'+' | b'-')
        || bytes[3] != b':'
        || ![bytes[1], bytes[2], bytes[4], bytes[5]]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return Err(invalid());
    }
    let hours = i16::from(bytes[1] - b'0') * 10 + i16::from(bytes[2] - b'0');
    let minutes = i16::from(bytes[4] - b'0') * 10 + i16::from(bytes[5] - b'0');
    if hours > 23 || minutes > 59 {
        return Err(invalid());
    }
    Ok((hours * 60 + minutes) * if bytes[0] == b'-' { -1 } else { 1 })
}

#[derive(Clone, Debug)]
pub struct ParserTimeRequirement {
    pub required: bool,
    pub hosts: Vec<Tainted<String>>,
    pub observed: Option<ParserTimeContext>,
}

fn invalid() -> AppError {
    AppError::Policy("enter a four-digit year (0001–9999) and a fixed UTC offset such as +01:00; IANA zones are not supported yet".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn context_is_bounded_and_preserves_its_closed_basis() {
        for basis in [
            ParserTimeBasis::Analyst,
            ParserTimeBasis::Command,
            ParserTimeBasis::ConfirmedSuggestion,
        ] {
            let context = ParserTimeContext::from_fields("2026", "-03:30", true, basis).unwrap();
            assert_eq!(context.offset_minutes(), -210);
            assert_eq!(context.offset_text(), "-03:30");
            assert_eq!(ParserTimeBasis::parse(basis.as_str()).unwrap(), basis);
        }
        for (year, offset) in [
            ("0000", "+00:00"),
            ("10000", "+00:00"),
            ("2026", "+24:00"),
            ("2026", "+01:60"),
            ("2026", "Europe/London"),
            ("2026", "+1:00"),
        ] {
            assert!(
                ParserTimeContext::from_fields(year, offset, true, ParserTimeBasis::Analyst)
                    .is_err()
            );
        }
        assert!(ParserTimeBasis::parse("untrusted free text").is_err());
    }
}

impl ParserTimeContext {
    /// A source-stated timestamp is a suggestion, never a confirmed ingestion choice.
    pub fn from_timestamp_hint(raw: &str) -> Option<Self> {
        let (local, offset) = if let Some(local) = raw.strip_suffix('Z') {
            (local, 0)
        } else {
            let split = raw.len().checked_sub(6)?;
            let local = raw.get(..split)?;
            (local, parse_offset(raw.get(split..)?).ok()?)
        };
        let whole = if let Some((whole, fraction)) = local.split_once('.') {
            if fraction.is_empty()
                || fraction.len() > 9
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            whole
        } else {
            local
        };
        irmind_domain::UtcTimestamp::parse(&format!("{whole}Z")).ok()?;
        Self::new(
            raw.get(..4)?.parse().ok()?,
            offset,
            true,
            ParserTimeBasis::ConfirmedSuggestion,
        )
        .ok()
    }
}

#[derive(Clone, Debug)]
pub struct ParserTimeSuggestion {
    pub context: ParserTimeContext,
    pub source_hash: String,
    pub record_index: usize,
    pub host: Tainted<String>,
}
