//! Analyst-authorized reads of authenticated original source records.
use crate::{AppError, CancellationToken, CaseId};
use irmind_domain::{EvidenceHash, SourceRecordV1, Tainted};
use std::path::Path;

pub trait SourceEvidenceReader: Send + Sync {
    /// An empty set selects the current case without authorizing a root.
    /// Only analyst-origin ingestion/verification may authorize actual hashes.
    fn authorize_local_root(
        &self,
        case_id: &CaseId,
        root: &Path,
        sources: &[EvidenceHash],
    ) -> Result<(), AppError>;

    fn read_verified_record(
        &self,
        case_id: &CaseId,
        source: &EvidenceHash,
        record_index: u64,
        cancel: &CancellationToken,
    ) -> Result<Tainted<SourceRecordV1>, AppError>;
}
