use crate::AppError;

/// Closed parser-owned capabilities; directory names never select a profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PartitionProfile {
    #[default]
    Unpartitioned,
    CloudAccountRegion,
    EndpointHost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartitionLimits {
    pub account: u16,
    pub region: u16,
    pub host: u16,
}

impl Default for PartitionLimits {
    fn default() -> Self {
        Self {
            account: 1024,
            region: 1024,
            host: 64,
        }
    }
}

impl PartitionLimits {
    pub fn validate(self) -> Result<(), AppError> {
        if [self.account, self.region, self.host]
            .iter()
            .any(|n| !(1..=1024).contains(n))
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidPartitionCap,
            ));
        }
        Ok(())
    }
}
