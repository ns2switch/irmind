use super::{CompiledSkill, SkillCompiler, SkillOrigin, SkillPackageStore, SkillServiceError};
use crate::{AppError, Engine, SignedOperation, hex};
use irmind_domain::{SkillName, SkillPackage, SkillResource};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const PREFIX: &str = "skill-installation-v1:";
pub(super) const MAX_OPERATION_BYTES: usize = 768 * 1024;
pub(super) const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;

#[cfg(test)]
#[path = "history_tests.rs"]
#[allow(clippy::unwrap_used)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireFile {
    path: String,
    contents: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub(super) format_version: u32,
    pub(super) name: String,
    pub(super) skill_version: String,
    pub(super) package_sha256: String,
    pub(super) origin: SkillOrigin,
    pub(super) active: bool,
    pub(super) previous_operation: Option<String>,
    files: Vec<WireFile>,
}

impl Snapshot {
    pub(super) fn new(skill: &CompiledSkill, origin: SkillOrigin) -> Self {
        Self {
            format_version: 1,
            name: skill.metadata().name().as_str().into(),
            skill_version: skill.metadata().version().as_str().into(),
            package_sha256: hex(skill.package().hash().as_bytes()),
            origin,
            active: true,
            previous_operation: None,
            files: skill
                .package()
                .resources()
                .values()
                .map(|file| WireFile {
                    path: file.path().as_str().into(),
                    contents: file.untrusted_text().into(),
                })
                .collect(),
        }
    }

    pub(super) fn package(&self) -> Result<SkillPackage, AppError> {
        if self.format_version != 1
            || self.files.len() > 17
            || self
                .files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(invalid());
        }
        let files = self
            .files
            .iter()
            .map(|file| {
                SkillResource::new(&file.path, file.contents.as_bytes()).map_err(AppError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let package = SkillPackage::new(files)?;
        if hex(package.hash().as_bytes()) != self.package_sha256 {
            return Err(invalid());
        }
        Ok(package)
    }

    pub(super) fn compile(&self, compiler: &dyn SkillCompiler) -> Result<CompiledSkill, AppError> {
        let skill = compiler.compile(self.package()?)?;
        if skill.metadata().name().as_str() != self.name
            || skill.metadata().version().as_str() != self.skill_version
        {
            return Err(invalid());
        }
        Ok(skill)
    }
}

pub(super) struct ApprovedSnapshot {
    pub(super) snapshot: Snapshot,
    pub(super) operation_hash: String,
}

#[derive(Default)]
pub struct ApprovedSkills {
    pub(super) latest: BTreeMap<SkillName, ApprovedSnapshot>,
    pub(super) versions: usize,
    pub(super) encoded_bytes: usize,
}

impl ApprovedSkills {
    pub fn names(&self) -> impl Iterator<Item = &SkillName> {
        self.latest.keys()
    }

    pub fn load_active(
        &self,
        name: &SkillName,
        store: &dyn SkillPackageStore,
        compiler: &dyn SkillCompiler,
    ) -> Result<CompiledSkill, AppError> {
        let approved = self
            .latest
            .get(name)
            .ok_or(SkillServiceError::NotInstalled)?;
        if !approved.snapshot.active {
            return Err(SkillServiceError::NotInstalled.into());
        }
        let stored = store
            .read_active(name)?
            .ok_or(SkillServiceError::StorageMismatch)?;
        if hex(stored.hash().as_bytes()) != approved.snapshot.package_sha256 {
            return Err(SkillServiceError::StorageMismatch.into());
        }
        let skill = approved.snapshot.compile(compiler)?;
        if skill.package() != &stored {
            return Err(SkillServiceError::StorageMismatch.into());
        }
        Ok(skill)
    }

    fn apply(
        &mut self,
        operation: &SignedOperation,
        compiler: &dyn SkillCompiler,
    ) -> Result<(), AppError> {
        let Some(payload) = operation.operation.strip_prefix(PREFIX) else {
            return Ok(());
        };
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(payload.len())
            .ok_or_else(invalid)?;
        self.versions = self.versions.checked_add(1).ok_or_else(invalid)?;
        if payload.len() > MAX_OPERATION_BYTES
            || self.encoded_bytes > MAX_HISTORY_BYTES
            || self.versions > 4096
        {
            return Err(SkillServiceError::HistoryLimit.into());
        }
        let bytes = hex::decode(payload).map_err(|_| invalid())?;
        if hex(&bytes) != payload {
            return Err(invalid());
        }
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if serde_json::to_vec(&snapshot).map_err(|_| invalid())? != bytes {
            return Err(invalid());
        }
        snapshot.compile(compiler)?;
        let name = SkillName::parse(&snapshot.name)?;
        let previous = self.latest.get(&name).map(|old| old.operation_hash.clone());
        if snapshot.previous_operation != previous {
            return Err(invalid());
        }
        self.latest.insert(
            name,
            ApprovedSnapshot {
                snapshot,
                operation_hash: hex(&operation.hash),
            },
        );
        if self.latest.len() > 256
            || self.latest.values().filter(|s| s.snapshot.active).count() > 32
        {
            return Err(SkillServiceError::HistoryLimit.into());
        }
        Ok(())
    }
}

impl Engine<'_> {
    pub fn approved_skills(
        &self,
        compiler: &dyn SkillCompiler,
    ) -> Result<ApprovedSkills, AppError> {
        let entries = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&entries)?;
        let mut approved = ApprovedSkills::default();
        for entry in &entries {
            approved.apply(entry, compiler)?;
        }
        for value in approved
            .latest
            .values()
            .filter(|s| s.snapshot.origin == SkillOrigin::Bundled)
        {
            let skill = value.snapshot.compile(compiler)?;
            if !self
                .skills
                .as_ref()
                .is_some_and(|services| services.verifies_bundle(&skill))
            {
                return Err(SkillServiceError::InvalidOrigin.into());
            }
        }
        Ok(approved)
    }
}

pub(super) fn invalid() -> AppError {
    SkillServiceError::InvalidHistory.into()
}
