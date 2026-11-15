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
    pub(crate) source: Option<Arc<dyn super::SkillCatalogSource>>,
    pub(crate) runtime_version: Option<String>,
}
impl CatalogServices {
    pub fn new(
        verifier: Arc<dyn CatalogIndexVerifier>,
        proofs: Arc<dyn CatalogProofStore>,
    ) -> Self {
        Self {
            verifier,
            proofs,
            source: None,
            runtime_version: None,
        }
    }
    pub fn with_source(
        mut self,
        source: Arc<dyn super::SkillCatalogSource>,
        runtime_version: &str,
    ) -> Result<Self, super::CatalogError> {
        self = self.with_runtime_version(runtime_version)?;
        self.source = Some(source);
        Ok(self)
    }
    pub fn with_runtime_version(mut self, version: &str) -> Result<Self, super::CatalogError> {
        super::version::Version::parse(version)?;
        self.runtime_version = Some(version.into());
        Ok(self)
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
        let version = self.runtime_version.as_deref().ok_or_else(|| {
            AppError::Policy(
                "Catalog runtime context is unavailable; review with the current IRMind version."
                    .into(),
            )
        })?;
        if !index
            .asset(skill.metadata().name().as_str())?
            .entry()
            .supports_version(version)?
        {
            return Err(AppError::Policy(
                "This catalog skill requires a newer IRMind version; it remains unavailable."
                    .into(),
            ));
        }
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
