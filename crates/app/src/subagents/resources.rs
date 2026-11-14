use super::SubagentRecordError;
use serde::{Deserialize, Serialize};

/// Rounds belong to the parent turn; the other resources belong to the case.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentResources {
    pub tokens: u64,
    pub calls: u64,
    pub rounds: u64,
    pub cloud_bytes: u64,
}
impl SubagentResources {
    pub fn validate(self) -> Result<(), SubagentRecordError> {
        if self.tokens > 10_000_000
            || self.calls > 10_000
            || self.rounds > 100
            || self.cloud_bytes > 10_995_116_277_760
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
    pub fn within(self, limit: Self) -> bool {
        self.tokens <= limit.tokens
            && self.calls <= limit.calls
            && self.rounds <= limit.rounds
            && self.cloud_bytes <= limit.cloud_bytes
    }
    pub fn checked_add(self, other: Self) -> Result<Self, SubagentRecordError> {
        let value = Self {
            tokens: self
                .tokens
                .checked_add(other.tokens)
                .ok_or(SubagentRecordError)?,
            calls: self
                .calls
                .checked_add(other.calls)
                .ok_or(SubagentRecordError)?,
            rounds: self
                .rounds
                .checked_add(other.rounds)
                .ok_or(SubagentRecordError)?,
            cloud_bytes: self
                .cloud_bytes
                .checked_add(other.cloud_bytes)
                .ok_or(SubagentRecordError)?,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn checked_sub(self, other: Self) -> Result<Self, SubagentRecordError> {
        Ok(Self {
            tokens: self
                .tokens
                .checked_sub(other.tokens)
                .ok_or(SubagentRecordError)?,
            calls: self
                .calls
                .checked_sub(other.calls)
                .ok_or(SubagentRecordError)?,
            rounds: self
                .rounds
                .checked_sub(other.rounds)
                .ok_or(SubagentRecordError)?,
            cloud_bytes: self
                .cloud_bytes
                .checked_sub(other.cloud_bytes)
                .ok_or(SubagentRecordError)?,
        })
    }
    /// Strictly greater than 25% of either remaining resource. Never divides.
    pub fn requires_signed_consent(self, remaining: Self) -> Result<bool, SubagentRecordError> {
        self.validate()?;
        remaining.validate()?;
        if !self.within(remaining) {
            return Err(SubagentRecordError);
        }
        Ok(u128::from(self.tokens) * 4 > u128::from(remaining.tokens)
            || u128::from(self.calls) * 4 > u128::from(remaining.calls))
    }
}
