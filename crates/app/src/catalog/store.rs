use super::{CatalogIndexBytes, CatalogProofId, VerifiedCatalogIndex};
use crate::{AppError, CancellationToken};
use irmind_domain::CaseId;

/// Immutable publisher proofs. Reads remain untrusted until index verification.
pub trait CatalogProofStore: Send + Sync {
    fn publish(
        &self,
        proof: &VerifiedCatalogIndex,
        cancel: &CancellationToken,
    ) -> Result<CatalogProofId, AppError>;
    fn read(
        &self,
        id: &CatalogProofId,
        cancel: &CancellationToken,
    ) -> Result<CatalogIndexBytes, AppError>;
    fn publish_for_case(
        &self,
        _case: &CaseId,
        _proof: &VerifiedCatalogIndex,
        _cancel: &CancellationToken,
    ) -> Result<CatalogProofId, AppError> {
        Err(AppError::Storage(
            "case catalog proof storage is unavailable".into(),
        ))
    }
    fn read_for_case(
        &self,
        _case: &CaseId,
        _id: &CatalogProofId,
        _cancel: &CancellationToken,
    ) -> Result<CatalogIndexBytes, AppError> {
        Err(AppError::Storage(
            "case catalog proof storage is unavailable".into(),
        ))
    }
}
