use super::history::{MAX_HISTORY_BYTES, MAX_OPERATION_BYTES, PREFIX, Snapshot, invalid};
use super::{
    CompiledSkill, SkillCompiler, SkillOrigin, SkillPackageStore, SkillServiceError, SkillStatus,
};
use crate::{AppError, CancellationToken, Engine};
use irmind_domain::SkillName;
use std::{collections::BTreeSet, path::Path};

impl Engine<'_> {
    pub fn preview_skill(
        &self,
        store: &dyn SkillPackageStore,
        compiler: &dyn SkillCompiler,
        directory: &Path,
        cancel: &CancellationToken,
    ) -> Result<CompiledSkill, AppError> {
        let skill = compiler.compile(store.read_candidate(directory, cancel)?)?;
        self.check_skill_content(&skill)?;
        Ok(skill)
    }

    pub fn install_skill(
        &self,
        store: &dyn SkillPackageStore,
        compiler: &dyn SkillCompiler,
        skill: &CompiledSkill,
        origin: SkillOrigin,
        reserved: &BTreeSet<String>,
    ) -> Result<SkillName, AppError> {
        self.require_attended_analyst("install skill")?;
        if origin == SkillOrigin::Bundled {
            return Err(SkillServiceError::InvalidOrigin.into());
        }
        // Recompile the exact preview bytes; callers cannot substitute metadata.
        let checked = compiler.compile(skill.package().clone())?;
        self.check_skill_content(&checked)?;
        if reserved.contains(checked.metadata().name().as_str()) {
            return Err(SkillServiceError::NameConflict.into());
        }
        let _lock = self.audit_log.lock_global_operations()?;
        let approved = self.approved_skills(compiler)?;
        if approved.latest.contains_key(checked.metadata().name())
            || self
                .skills
                .as_ref()
                .is_some_and(|s| s.bundled.contains_key(checked.metadata().name()))
        {
            return Err(SkillServiceError::NameConflict.into());
        }
        self.commit_skill_snapshot(store, compiler, &Snapshot::new(&checked, origin))
    }

    pub fn update_skill(
        &self,
        store: &dyn SkillPackageStore,
        compiler: &dyn SkillCompiler,
        skill: &CompiledSkill,
    ) -> Result<SkillName, AppError> {
        self.require_attended_analyst("update skill")?;
        let checked = compiler.compile(skill.package().clone())?;
        self.check_skill_content(&checked)?;
        let _lock = self.audit_log.lock_global_operations()?;
        let approved = self.approved_skills(compiler)?;
        let old = approved.latest.get(checked.metadata().name());
        if old.is_none()
            && !self
                .skills
                .as_ref()
                .is_some_and(|s| s.bundled.contains_key(checked.metadata().name()))
        {
            return Err(SkillServiceError::NotInstalled.into());
        }
        let origin = old.map_or(SkillOrigin::Analyst, |s| match s.snapshot.origin {
            SkillOrigin::Bundled => SkillOrigin::Analyst,
            value => value,
        });
        let mut snapshot = Snapshot::new(&checked, origin);
        snapshot.active = old.is_none_or(|s| s.snapshot.active);
        snapshot.previous_operation = old.map(|s| s.operation_hash.clone());
        self.commit_skill_snapshot(store, compiler, &snapshot)
    }

    pub fn set_skill_active(
        &self,
        store: &dyn SkillPackageStore,
        compiler: &dyn SkillCompiler,
        name: &SkillName,
        active: bool,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("change skill activation")?;
        let _lock = self.audit_log.lock_global_operations()?;
        let approved = self.approved_skills(compiler)?;
        let old = approved
            .latest
            .get(name)
            .ok_or(SkillServiceError::NotInstalled)?;
        let mut snapshot = old.snapshot.clone();
        if active {
            if old.snapshot.active {
                approved.load_active(name, store, compiler)?;
            } else if store.read_active(name)?.is_some() {
                return Err(SkillServiceError::StorageMismatch.into());
            }
            self.check_skill_content(&snapshot.compile(compiler)?)?;
        }
        snapshot.active = active;
        snapshot.previous_operation = Some(old.operation_hash.clone());
        self.commit_skill_snapshot(store, compiler, &snapshot)
            .map(|_| ())
    }

    /// Explicit restoration only; inspection never repairs a loose file.
    pub fn restore_skill(
        &self,
        store: &dyn SkillPackageStore,
        compiler: &dyn SkillCompiler,
        name: &SkillName,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("restore skill")?;
        let _lock = self.audit_log.lock_global_operations()?;
        let approved = self.approved_skills(compiler)?;
        let old = approved
            .latest
            .get(name)
            .ok_or(SkillServiceError::NotInstalled)?;
        let skill = old.snapshot.compile(compiler)?;
        self.check_skill_content(&skill)?;
        if old.snapshot.active {
            store.publish(name, skill.package())
        } else {
            store.deactivate(name)
        }
    }

    pub(in crate::skills) fn commit_skill_snapshot(
        &self,
        store: &dyn SkillPackageStore,
        compiler: &dyn SkillCompiler,
        snapshot: &Snapshot,
    ) -> Result<SkillName, AppError> {
        let approved = self.approved_skills(compiler)?;
        let name = SkillName::parse(&snapshot.name)?;
        if approved.latest.len() >= 256 && !approved.latest.contains_key(&name)
            || approved.versions >= 4096
        {
            return Err(SkillServiceError::HistoryLimit.into());
        }
        let mut count = approved
            .latest
            .iter()
            .filter(|(n, s)| **n != name && s.snapshot.active)
            .count();
        if let Some(services) = &self.skills {
            count += services
                .bundled
                .keys()
                .filter(|n| **n != name && !approved.latest.contains_key(*n))
                .count();
        }
        if snapshot.active && count >= 32 {
            return Err(SkillServiceError::ActiveLimit.into());
        }
        let package = snapshot.package()?;
        let payload = hex::encode(serde_json::to_vec(&snapshot).map_err(|_| invalid())?);
        if payload.len() > MAX_OPERATION_BYTES
            || approved
                .encoded_bytes
                .checked_add(payload.len())
                .is_none_or(|n| n > MAX_HISTORY_BYTES)
        {
            return Err(SkillServiceError::HistoryLimit.into());
        }
        self.append_global_operation_unlocked(format!("{PREFIX}{payload}"))?;
        if snapshot.active {
            store.publish(&name, &package)?;
        } else {
            store.deactivate(&name)?;
        }
        Ok(name)
    }

    pub fn skill_statuses(
        &self,
        store: &dyn SkillPackageStore,
        compiler: &dyn SkillCompiler,
    ) -> Result<Vec<SkillStatus>, AppError> {
        let approved = self.approved_skills(compiler)?;
        let mut statuses = Vec::new();
        for (name, old) in &approved.latest {
            let loaded = (|| {
                let skill = if old.snapshot.active {
                    approved.load_active(name, store, compiler)?
                } else {
                    if store.read_active(name)?.is_some() {
                        return Err(AppError::from(SkillServiceError::StorageMismatch));
                    }
                    old.snapshot.compile(compiler)?
                };
                self.check_skill_content(&skill)?;
                Ok(skill)
            })();
            let description = match &loaded {
                Ok(skill) => self.guard.screen(skill.metadata().description())?,
                Err(_) => crate::Screened {
                    text: String::new(),
                    detections: Vec::new(),
                },
            };
            statuses.push(SkillStatus {
                name: name.clone(),
                version: old.snapshot.skill_version.clone(),
                sha256: old.snapshot.package_sha256.clone(),
                origin: old.snapshot.origin,
                active: old.snapshot.active,
                available: loaded.is_ok() && description.detections.is_empty(),
                description: description.text,
                warning: loaded.err().map(|_| {
                    "Skill file is missing, changed or unsupported; restore or review it.".into()
                }),
            });
        }
        for name in store.names()? {
            if !approved.latest.contains_key(&name) {
                statuses.push(SkillStatus {
                    name,
                    version: String::new(),
                    sha256: String::new(),
                    origin: SkillOrigin::Analyst,
                    active: false,
                    available: false,
                    description: String::new(),
                    warning: Some(
                        "Unsigned skill is disabled; review it before installation.".into(),
                    ),
                });
            }
        }
        Ok(statuses)
    }
}
