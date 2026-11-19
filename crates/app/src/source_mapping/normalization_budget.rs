//! Closed resource admission profiles; deliberately absent from signed formats.
use crate::{AppError, FixedAppError};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizedExpansionProfile {
    CompactFlow32,
    DecodedJson16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedSourceBudget {
    decoded_bytes: u64,
    profile: NormalizedExpansionProfile,
}
impl NormalizedSourceBudget {
    pub const MAX_DECODED_BYTES: u64 = 50 * 1024 * 1024 * 1024;
    pub fn try_new(
        decoded_bytes: u64,
        profile: NormalizedExpansionProfile,
    ) -> Result<Self, AppError> {
        if decoded_bytes > Self::MAX_DECODED_BYTES {
            return Err(AppError::Fixed(FixedAppError::SourceLimit));
        }
        Ok(Self {
            decoded_bytes,
            profile,
        })
    }
    pub const fn decoded_bytes(self) -> u64 {
        self.decoded_bytes
    }
    pub const fn profile(self) -> NormalizedExpansionProfile {
        self.profile
    }
    pub fn allowance(self) -> Result<u64, AppError> {
        let factor = match self.profile {
            NormalizedExpansionProfile::CompactFlow32 => 32,
            NormalizedExpansionProfile::DecodedJson16 => 16,
        };
        self.decoded_bytes
            .checked_mul(factor)
            .and_then(|n| n.checked_add(64 * 1024 * 1024))
            .ok_or(AppError::Fixed(
                FixedAppError::StorageNormalizedStagingSpace,
            ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_budget_boundaries_are_checked() -> Result<(), AppError> {
        let profile = NormalizedExpansionProfile::CompactFlow32;
        assert_eq!(
            NormalizedSourceBudget::try_new(0, profile)?.allowance()?,
            64 * 1024 * 1024
        );
        let max = NormalizedSourceBudget::MAX_DECODED_BYTES;
        assert_eq!(
            NormalizedSourceBudget::try_new(max, profile)?.allowance()?,
            max * 32 + 64 * 1024 * 1024
        );
        assert!(NormalizedSourceBudget::try_new(max + 1, profile).is_err());
        assert!(NormalizedSourceBudget::try_new(u64::MAX, profile).is_err());
        Ok(())
    }
}
