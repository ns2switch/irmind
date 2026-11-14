//! A case owns its publisher proof before its first catalog snapshot is signed.
use super::ResolvedSkill;
use crate::catalog::CatalogProofRequirement;
use crate::{Actor, AppError, CancellationToken, CaseId, Engine, SkillReceiptVerifier};

impl Engine<'_> {
    pub(super) fn pin_catalog_proof(
        &self,
        id: &CaseId,
        resolved: &ResolvedSkill,
        state: &SkillReceiptVerifier,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let Some(index) = &resolved.catalog else {
            return Ok(());
        };
        let services = self
            .skills
            .as_ref()
            .and_then(|s| s.catalog.as_ref())
            .ok_or(crate::catalog::CatalogError::Unavailable)?;
        let required = state.admissions();
        let mut admissions: Vec<_> = self
            .audit_log
            .global_operations()?
            .into_iter()
            .filter(|p| required.contains(&crate::hex(&p.hash)))
            .collect();
        admissions.sort_by_key(|p| p.hash);
        let analyst = self.verifier.trusted_public_key(&Actor::Analyst)?;
        let requirements =
            state.catalog_requirements(&admissions, self.verifier.as_ref(), &analyst)?;
        if !requirements.iter().any(|r| r.proof() == index.proof_id()) {
            let published = services.proofs.publish_for_case(id, index, cancel)?;
            if published != index.proof_id() {
                return Err(super::super::receipts::invalid());
            }
        }
        // A missing or changed already referenced copy is an error, never a request
        // to repair it from mutable global storage.
        let requirement = CatalogProofRequirement::new(index.proof_id(), index.index().tag())?;
        let checked = services.read_case(id, &requirement, cancel)?;
        if checked.proof_id() != index.proof_id() {
            return Err(super::super::receipts::invalid());
        }
        Ok(())
    }
}
