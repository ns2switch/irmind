//! V8 carries exactly the case-local publisher indices used by skill snapshots.
use super::{AppError, CancellationToken, storage};
use irmind_app::{
    SignedOperation, SkillReceiptVerifier, Verifier,
    catalog::{
        CatalogIndexVerifier, CatalogProofReader, VerifiedCatalogIndex, catalog_proof_chunk,
        catalog_proof_descriptor,
    },
};
use std::{fs::File, io::Write as _};

pub(super) fn write(
    output: &mut File,
    indices: &[VerifiedCatalogIndex],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    output
        .write_all(&(indices.len() as u64).to_be_bytes())
        .map_err(storage)?;
    for index in indices {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        super::export_current::write_frame(output, &catalog_proof_descriptor(index)?)?;
        for ordinal in 0..index.raw().index().len().div_ceil(256 * 1024) as u64 {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            super::export_current::write_frame(output, &catalog_proof_chunk(index, ordinal)?)?;
        }
    }
    Ok(())
}

pub(super) fn read(
    input: &mut File,
    checked: &mut SkillReceiptVerifier,
    proofs: &[SignedOperation],
    verifier: &dyn Verifier,
    analyst: &[u8],
    catalog_verifier: &dyn CatalogIndexVerifier,
) -> Result<(), AppError> {
    super::skill_proofs::verify_bundled(checked)?;
    let requirements = checked.catalog_requirements(proofs, verifier, analyst)?;
    let count = super::frames::read_u64(input)?;
    if count != requirements.len() as u64 || count > 256 {
        return Err(AppError::InvalidChain(0));
    }
    let mut indices = Vec::with_capacity(requirements.len());
    let mut total = 0u64;
    for requirement in requirements {
        let bytes = super::frames::read_frame(input)?;
        let mut reader = CatalogProofReader::new(&bytes, requirement.proof())?;
        total = total
            .checked_add(reader.index_bytes() + 72)
            .ok_or(AppError::InvalidChain(0))?;
        if total > 16 * 1024 * 1024 {
            return Err(AppError::InvalidChain(0));
        }
        for _ in 0..reader.chunk_count() {
            reader.accept(&super::frames::read_frame(input)?)?;
        }
        indices.push(reader.finish(&requirement, catalog_verifier)?);
    }
    checked.verify_catalog_admissions(
        proofs,
        &indices,
        verifier,
        analyst,
        &crate::TomlSkillCompiler,
    )
}
