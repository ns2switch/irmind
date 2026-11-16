//! Analyst-only logical deletion. A durable signed receipt precedes every removal.
mod engine;
mod receipt;
use crate::{AppError, CancellationToken, CaseId, CaseLock, SignedOperation};
pub use receipt::CaseDeletedV1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseDeletionInventory {
    pub case_id: CaseId,
    pub title: String,
    pub created_at: u64,
    pub last_chain_hash: String,
    pub entry_count: u64,
    pub source_count: u64,
    pub owned_file_bytes: u64,
    pub shared_blob_bytes: u64,
    pub logical_metadata_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct DeletionProgress {
    pub case_id: CaseId,
    pub complete: bool,
    pub message: String,
}
/// Only the application can issue this after authenticating the global journal.
#[derive(Clone)]
pub struct VerifiedCaseDeletion {
    operation: SignedOperation,
    receipt: CaseDeletedV1,
}
impl VerifiedCaseDeletion {
    pub fn operation(&self) -> &SignedOperation {
        &self.operation
    }
    pub fn receipt(&self) -> &CaseDeletedV1 {
        &self.receipt
    }
}

pub trait CaseLifecycleStore: Send + Sync {
    fn open_session(&self, id: &CaseId) -> Result<Box<dyn CaseLock>, AppError>;
    fn prepare_deletion(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn PreparedCaseDeletion + '_>, AppError>;
    fn resume_deletion(
        &self,
        deletion: &VerifiedCaseDeletion,
        cancel: &CancellationToken,
    ) -> Result<DeletionProgress, AppError>;
}
pub trait PreparedCaseDeletion: Send {
    fn inventory(&self) -> &CaseDeletionInventory;
    fn commit(self: Box<Self>, operation: &SignedOperation) -> Result<DeletionProgress, AppError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CaseLifecycleError {
    #[error("Case deletion is unavailable in this storage adapter.")]
    Unavailable,
    #[error("This case is open or busy in another process. Close it there and retry.")]
    Busy,
    #[error(
        "This case has a signed deletion intent. Use /cases deleted to inspect or retry cleanup."
    )]
    Deleted,
    #[error("Type the exact case title or identifier before signing deletion.")]
    Confirmation,
    #[error(
        "The deletion receipt or prepared inventory is invalid or has changed. Nothing was deleted."
    )]
    InvalidReceipt,
    #[error(
        "A link, reparse point, or unsupported entry was found in case storage. Cleanup stopped; inspect the entry and retry."
    )]
    UnsafeEntry,
    #[error(
        "Case storage exceeds the bounded deletion scan. Nothing outside case storage was removed."
    )]
    ScanLimit,
}
