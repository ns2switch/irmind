use super::super::{AppError, ParquetProfile, invalid_source};
use std::sync::{Arc, atomic::Ordering};

/// Logical live temporary bytes, including overlapping sort runs. File owners
/// declare this field after their temporary path so unlink precedes accounting.
pub(in crate::parquet_store) struct DiskLease {
    profile: Option<Arc<ParquetProfile>>,
    bytes: u64,
}
impl DiskLease {
    pub(in crate::parquet_store) fn new(profile: Option<Arc<ParquetProfile>>) -> Self {
        Self { profile, bytes: 0 }
    }
    pub(in crate::parquet_store) fn add(&mut self, bytes: u64) -> Result<(), AppError> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(invalid_source)?;
        if let Some(profile) = &self.profile {
            let total = profile
                .staging_live
                .fetch_add(bytes, Ordering::Relaxed)
                .saturating_add(bytes);
            profile.record_staging_peak(total);
        }
        Ok(())
    }
    pub(super) fn clear(&mut self) {
        if let Some(profile) = &self.profile {
            profile
                .staging_live
                .fetch_sub(self.bytes, Ordering::Relaxed);
        }
        self.bytes = 0;
    }
}
impl Drop for DiskLease {
    fn drop(&mut self) {
        self.clear();
    }
}
