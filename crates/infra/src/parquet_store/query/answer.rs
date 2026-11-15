//! Private scan status remains separate from rendered evidence and text.
use super::{AppError, ScanStatus};
use irmind_app::subagents::TaskQueryPartialReason;

pub(crate) struct QueryAnswer<T> {
    pub(crate) value: T,
    pub(crate) reason: Option<TaskQueryPartialReason>,
}
impl<T> QueryAnswer<T> {
    pub(in crate::parquet_store) fn complete(value: T) -> Self {
        Self {
            value,
            reason: None,
        }
    }
    pub(in crate::parquet_store) fn partial(value: T, reason: TaskQueryPartialReason) -> Self {
        Self {
            value,
            reason: Some(reason),
        }
    }
    pub(in crate::parquet_store) fn scanned(value: T, status: ScanStatus) -> Self {
        if status == ScanStatus::Deadline {
            Self::partial(value, TaskQueryPartialReason::Deadline)
        } else {
            Self::complete(value)
        }
    }
    /// Existing graph APIs retain their error on an exhausted scan deadline.
    pub(in crate::parquet_store) fn strict(self) -> Result<T, AppError> {
        if self.reason == Some(TaskQueryPartialReason::Deadline) {
            super::complete(ScanStatus::Deadline)?;
        }
        Ok(self.value)
    }
    pub(in crate::parquet_store) fn try_map<U>(
        self,
        map: impl FnOnce(T) -> Result<U, AppError>,
    ) -> Result<QueryAnswer<U>, AppError> {
        Ok(QueryAnswer {
            value: map(self.value)?,
            reason: self.reason,
        })
    }
}
