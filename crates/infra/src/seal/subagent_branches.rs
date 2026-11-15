//! Exact authenticated V8 branch tails. No model or downloaded code is invoked.
use super::{AppError, CancellationToken, CaseId, LocalStore, LocalVerifier, storage};
use irmind_app::{
    SkillReceiptVerifier, Verifier,
    subagents::{BranchMaterialVerifier, SubagentBranchStore, SubagentJournal},
};
use std::{collections::BTreeMap, fs::File, io::Write as _};

pub(super) fn write(
    store: &LocalStore,
    case: &CaseId,
    analyst: &[u8],
    skills: &mut SkillReceiptVerifier,
    out: &mut File,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let mut verifier = LocalVerifier {
        trusted: BTreeMap::new(),
    }
    .with_trusted_key(&irmind_domain::Actor::Analyst, analyst)?;
    let mut journal =
        SubagentJournal::for_verification(case.clone()).map_err(|_| AppError::InvalidChain(0))?;
    store.for_each_audit_entry(case, |entry| {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        verifier = verifier
            .clone()
            .with_trusted_key(&entry.actor, &entry.public_key)?;
        journal.accept(&entry, &verifier)
    })?;
    let mut material =
        BranchMaterialVerifier::new(&journal).map_err(|_| AppError::InvalidChain(0))?;
    out.write_all(&(material.count() as u64).to_be_bytes())
        .map_err(storage)?;
    while let Some(reference) = material
        .next_reference()
        .map_err(|_| AppError::InvalidChain(0))?
    {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let descriptor = material
            .next_descriptor()
            .map_err(|_| AppError::InvalidChain(0))?
            .ok_or(AppError::InvalidChain(0))?;
        let bytes = store.parquet.read(case, &reference, cancel)?;
        material
            .accept(
                &descriptor,
                bytes.as_bytes(),
                &verifier,
                skills,
                &crate::TomlSkillCompiler,
            )
            .map_err(|_| AppError::InvalidChain(0))?;
        super::export_current::write_frame(out, &descriptor)?;
        super::export_current::write_frame(out, bytes.as_bytes())?;
    }
    material.finish().map_err(|_| AppError::InvalidChain(0))
}

pub(super) fn read(
    input: &mut File,
    journal: &SubagentJournal,
    verifier: &dyn Verifier,
    skills: &mut SkillReceiptVerifier,
) -> Result<(), AppError> {
    let mut material =
        BranchMaterialVerifier::new(journal).map_err(|_| AppError::InvalidChain(0))?;
    if super::frames::read_u64(input)? != material.count() as u64 {
        return Err(AppError::InvalidChain(0));
    }
    for _ in 0..material.count() {
        let descriptor = super::frames::read_frame(input)?;
        let bytes = super::frames::read_frame(input)?;
        material
            .accept(
                &descriptor,
                &bytes,
                verifier,
                skills,
                &crate::TomlSkillCompiler,
            )
            .map_err(|_| AppError::InvalidChain(0))?;
    }
    material.finish().map_err(|_| AppError::InvalidChain(0))
}
