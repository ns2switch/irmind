use super::{
    CatalogIndexVerifier, CatalogProofId, CatalogProofStore, FrozenCatalogRelease,
    VerifiedCatalogIndex,
};
use crate::{AppError, CancellationToken, CaseId};
use std::sync::Arc;

/// Explicit local capabilities. Reading a proof never initiates a download.
#[derive(Clone)]
pub struct CatalogServices {
    pub(crate) verifier: Arc<dyn CatalogIndexVerifier>,
    pub(crate) proofs: Arc<dyn CatalogProofStore>,
}
impl CatalogServices {
    pub fn new(
        verifier: Arc<dyn CatalogIndexVerifier>,
        proofs: Arc<dyn CatalogProofStore>,
    ) -> Self {
        Self { verifier, proofs }
    }
    pub(crate) fn read_global(
        &self,
        receipt: &super::CatalogReceipt,
        skill: &crate::CompiledSkill,
        cancel: &CancellationToken,
    ) -> Result<VerifiedCatalogIndex, AppError> {
        let raw = self.proofs.read(&receipt.proof_id(), cancel)?;
        let index = self
            .verifier
            .verify(&raw, &FrozenCatalogRelease::new(receipt.release_tag())?)?;
        receipt.check(&index, skill)?;
        Ok(index)
    }
    pub(crate) fn read_case(
        &self,
        case: &CaseId,
        requirement: &CatalogProofRequirement,
        cancel: &CancellationToken,
    ) -> Result<VerifiedCatalogIndex, AppError> {
        let raw = self
            .proofs
            .read_for_case(case, &requirement.proof, cancel)?;
        self.verifier.verify(&raw, &requirement.release)
    }
}
/// Authenticated admission's required proof; no publisher trust is implied yet.
pub struct CatalogProofRequirement {
    proof: CatalogProofId,
    release: FrozenCatalogRelease,
}
impl CatalogProofRequirement {
    pub(crate) fn new(proof: CatalogProofId, tag: &str) -> Result<Self, AppError> {
        Ok(Self {
            proof,
            release: FrozenCatalogRelease::new(tag)?,
        })
    }
    pub const fn proof(&self) -> CatalogProofId {
        self.proof
    }
    pub const fn release(&self) -> &FrozenCatalogRelease {
        &self.release
    }
}
