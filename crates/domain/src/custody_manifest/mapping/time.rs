use super::{DomainError, invalid};
use crate::custody_manifest::{Reader, put};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceTimeBasisV1 {
    Analyst,
    Command,
    ConfirmedSuggestion,
}
impl SourceTimeBasisV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analyst => "analyst",
            Self::Command => "command",
            Self::ConfirmedSuggestion => "confirmed-suggestion",
        }
    }
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "analyst" => Ok(Self::Analyst),
            "command" => Ok(Self::Command),
            "confirmed-suggestion" => Ok(Self::ConfirmedSuggestion),
            _ => Err(invalid()),
        }
    }
}
/// Confirmed decoding inputs, independent of a source-specific display string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTimeContextV1 {
    year: u16,
    offset_minutes: i16,
    rollover: bool,
    basis: SourceTimeBasisV1,
}
impl SourceTimeContextV1 {
    pub fn try_new(
        year: u16,
        offset_minutes: i16,
        rollover: bool,
        basis: SourceTimeBasisV1,
    ) -> Result<Self, DomainError> {
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
    pub const fn year(self) -> u16 {
        self.year
    }
    pub const fn offset_minutes(self) -> i16 {
        self.offset_minutes
    }
    pub const fn rollover(self) -> bool {
        self.rollover
    }
    pub const fn basis(self) -> SourceTimeBasisV1 {
        self.basis
    }
    pub fn snapshot(self) -> String {
        format!(
            "source-time-v1;year={:04};offset={};rollover={};basis={}",
            self.year,
            self.offset_minutes,
            u8::from(self.rollover),
            self.basis.as_str()
        )
    }
    pub fn parse(snapshot: &str) -> Result<Self, DomainError> {
        if snapshot.len() > 128 {
            return Err(invalid());
        }
        let mut fields = snapshot.split(';');
        if fields.next() != Some("source-time-v1") {
            return Err(invalid());
        }
        let year = fields
            .next()
            .and_then(|s| s.strip_prefix("year="))
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let offset = fields
            .next()
            .and_then(|s| s.strip_prefix("offset="))
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let rollover = match fields.next() {
            Some("rollover=0") => false,
            Some("rollover=1") => true,
            _ => return Err(invalid()),
        };
        let basis = SourceTimeBasisV1::parse(
            fields
                .next()
                .and_then(|s| s.strip_prefix("basis="))
                .ok_or_else(invalid)?,
        )?;
        let result = Self::try_new(year, offset, rollover, basis)?;
        if fields.next().is_some() || result.snapshot() != snapshot {
            return Err(invalid());
        }
        Ok(result)
    }
    pub(super) fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&u64::from(self.year).to_be_bytes());
        out.extend_from_slice(&i64::from(self.offset_minutes).to_be_bytes());
        out.push(u8::from(self.rollover));
        put(out, self.basis.as_str().as_bytes());
    }
    pub(super) fn read(reader: &mut Reader<'_>) -> Result<Self, DomainError> {
        let year = u16::try_from(reader.u64()?).map_err(|_| invalid())?;
        let offset = i64::from_be_bytes(reader.u64()?.to_be_bytes());
        Self::try_new(
            year,
            i16::try_from(offset).map_err(|_| invalid())?,
            reader.bool()?,
            SourceTimeBasisV1::parse(&reader.string_limit(32)?)?,
        )
    }
}
