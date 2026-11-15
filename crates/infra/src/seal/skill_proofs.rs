//! V8 carries only signed admissions referenced by current methodology snapshots.
use super::{AppError, AuditLog, CancellationToken, CaseId, LocalStore, LocalVerifier, storage};
use irmind_app::{
    SignedOperation, SkillReceiptVerifier, Verifier,
    catalog::{
        CatalogIndexVerifier, CatalogProofStore, FrozenCatalogRelease, VerifiedCatalogIndex,
    },
    hex, skill_admission_references,
};
use std::{collections::BTreeMap, fs::File, io::Write as _};
pub(super) fn write(
    store: &LocalStore,
    case: &CaseId,
    analyst: &[u8],
    out: &mut File,
    cancel: &CancellationToken,
) -> Result<(Vec<VerifiedCatalogIndex>, SkillReceiptVerifier), AppError> {
    let entries = store.entries(case)?;
    let mut checked = SkillReceiptVerifier::default();
    for entry in &entries {
        checked.accept(entry, &crate::TomlSkillCompiler)?;
    }
    verify_bundled(&checked)?;
    let required = skill_admission_references(&entries)?;
    let mut proofs: Vec<_> = store
        .global_operations()?
        .into_iter()
        .filter(|p| required.contains(&hex(&p.hash)))
        .collect();
    proofs.sort_by_key(|p| p.hash);
    let verifier = LocalVerifier {
        trusted: BTreeMap::new(),
    };
    let requirements = checked.catalog_requirements(&proofs, &verifier, analyst)?;
    let mut indices = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        let raw = store.read_for_case(case, &requirement.proof(), cancel)?;
        indices.push(store.catalog_verifier.verify(
            &raw,
            &FrozenCatalogRelease::new(requirement.release().tag())?,
        )?);
    }
    checked.verify_catalog_admissions(
        &proofs,
        &indices,
        &verifier,
        analyst,
        &crate::TomlSkillCompiler,
    )?;
    out.write_all(&(proofs.len() as u64).to_be_bytes())
        .map_err(storage)?;
    for proof in proofs {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        super::export_current::write_frame(out, &serde_json::to_vec(&proof).map_err(storage)?)?;
    }
    Ok((indices, checked))
}
pub(super) fn read(
    input: &mut File,
    checked: &SkillReceiptVerifier,
    verifier: &dyn Verifier,
    analyst: &[u8],
) -> Result<Vec<SignedOperation>, AppError> {
    let count = super::frames::read_u64(input)?;
    if count != checked.admissions().len() as u64 || count > 256 {
        return Err(AppError::InvalidChain(0));
    }
    let mut proofs = Vec::new();
    for _ in 0..count {
        let bytes = super::frames::read_frame(input)?;
        let proof: SignedOperation = serde_json::from_slice(&bytes).map_err(storage)?;
        if serde_json::to_vec(&proof).map_err(storage)? != bytes {
            return Err(AppError::InvalidChain(0));
        }
        proofs.push(proof);
    }
    checked.catalog_requirements(&proofs, verifier, analyst)?;
    Ok(proofs)
}

pub(super) fn verify_bundled(checked: &SkillReceiptVerifier) -> Result<(), AppError> {
    let packages = crate::bundled_skill_candidates()?
        .into_iter()
        .map(|s| s.package().clone())
        .collect::<Vec<_>>();
    checked.verify_bundled(&packages, &crate::TomlSkillCompiler)
}
