//! V7 carries only signed admissions referenced by case methodology snapshots.
use super::{AppError, AuditLog, CancellationToken, CaseId, LocalStore, LocalVerifier, storage};
use irmind_app::{
    SignedOperation, SkillReceiptVerifier, Verifier, hex, skill_admission_references,
};
use std::{collections::BTreeMap, fs::File, io::Write as _};
pub(super) fn write(
    store: &LocalStore,
    case: &CaseId,
    analyst: &[u8],
    out: &mut File,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let entries = store.entries(case)?;
    let mut checked = SkillReceiptVerifier::default();
    for entry in &entries {
        checked.accept(entry, &crate::TomlSkillCompiler)?;
    }
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
    checked.verify_admissions(&proofs, &verifier, analyst)?;
    out.write_all(&(proofs.len() as u64).to_be_bytes())
        .map_err(storage)?;
    for proof in proofs {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        super::export_current::write_frame(out, &serde_json::to_vec(&proof).map_err(storage)?)?;
    }
    Ok(())
}
pub(super) fn read(
    input: &mut File,
    checked: &SkillReceiptVerifier,
    verifier: &dyn Verifier,
    analyst: &[u8],
) -> Result<(), AppError> {
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
    checked.verify_admissions(&proofs, verifier, analyst)
}
