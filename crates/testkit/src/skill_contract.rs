//! Offline contracts shared by skill compilers and local package stores.
use irmind_app::{AppError, CancellationToken, SkillCompiler, SkillPackageStore};
use irmind_domain::{SkillName, SkillPackage, SkillResource};
use std::path::Path;

pub fn run_skill_compiler_contract(
    compiler: &dyn SkillCompiler,
    package: &SkillPackage,
) -> Result<(), String> {
    let preview = compiler
        .compile(package.clone())
        .map_err(|e| e.to_string())?;
    let repeated = compiler
        .compile(package.clone())
        .map_err(|e| e.to_string())?;
    if preview.package() != package
        || repeated.package() != package
        || preview.metadata() != repeated.metadata()
        || preview.body_offset() != repeated.body_offset()
    {
        return Err("skill compiler changed immutable preview bytes or metadata".into());
    }
    for file in package.resources().values() {
        if format!("{preview:?}").contains(file.untrusted_text()) {
            return Err("skill Debug exposed resource content".into());
        }
    }
    let invalid =
        SkillPackage::new([
            SkillResource::new("SKILL.md", b"PRIVATE_CONTRACT_INVALID_HEADER")
                .map_err(|e| e.to_string())?,
        ])
        .map_err(|e| e.to_string())?;
    let error = compiler
        .compile(invalid)
        .err()
        .ok_or("invalid header was accepted")?;
    if format!("{error:?}{error}").contains("PRIVATE_CONTRACT_INVALID_HEADER") {
        return Err("skill compiler error exposed resource content".into());
    }
    Ok(())
}

/// Run against a fresh store and a candidate directory containing `first`.
pub fn run_skill_store_contract(
    store: &dyn SkillPackageStore,
    name: &SkillName,
    directory: &Path,
    first: &SkillPackage,
    second: &SkillPackage,
) -> Result<(), String> {
    let run = || -> Result<(), AppError> {
        let cancel = CancellationToken::new();
        if store.read_candidate(directory, &cancel)? != *first {
            return Err(irmind_app::SkillServiceError::StorageMismatch.into());
        }
        store.publish(name, first)?;
        if store.read_active(name)? != Some(first.clone()) {
            return Err(irmind_app::SkillServiceError::StorageMismatch.into());
        }
        store.publish(name, second)?;
        if store.read_active(name)? != Some(second.clone()) || store.names()? != [name.clone()] {
            return Err(irmind_app::SkillServiceError::StorageMismatch.into());
        }
        store.deactivate(name)?;
        if store.read_active(name)?.is_some() || !store.names()?.is_empty() {
            return Err(irmind_app::SkillServiceError::StorageMismatch.into());
        }
        cancel.cancel();
        if !matches!(
            store.read_candidate(directory, &cancel),
            Err(AppError::Cancelled)
        ) {
            return Err(irmind_app::SkillServiceError::StorageMismatch.into());
        }
        if store.clean_temporary()? != 0 {
            return Err(irmind_app::SkillServiceError::StorageMismatch.into());
        }
        Ok(())
    };
    run().map_err(|e| e.to_string())
}
