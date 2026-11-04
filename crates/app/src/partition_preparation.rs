use crate::{AppError, CaseId, StreamingEventParser};
use irmind_domain::ParquetArtifact;
use std::path::Path;

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

pub struct LocalBatchRequest<'a> {
    pub case_id: &'a CaseId,
    pub source_root: &'a Path,
    pub relative_paths: &'a [String],
    pub copy_original: bool,
    pub parser: &'a dyn StreamingEventParser,
    pub committed_artifacts: &'a [ParquetArtifact],
    pub limits: PartitionLimits,
}

impl LocalBatchRequest<'_> {
    pub fn validate(&self) -> Result<(), AppError> {
        self.limits.validate()?;
        if self.relative_paths.len() > 4 || !self.relative_paths.windows(2).all(|p| p[0] < p[1]) {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidPartitionBatch,
            ));
        }
        Ok(())
    }
}
