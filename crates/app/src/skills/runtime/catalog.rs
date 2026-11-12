use super::{ResolvedSkill, SkillServices};
use crate::{AppError, CompiledSkill, Engine, SkillOrigin, SkillSnapshotV1, SkillStatus};
use irmind_domain::SkillName;
impl Engine<'_> {
    pub(crate) fn resolve_skill(&self, name: &SkillName) -> Result<ResolvedSkill, AppError> {
        let services = self
            .skills
            .as_ref()
            .ok_or(super::super::SkillServiceError::NotInstalled)?;
        let approved = self.approved_skills(services.compiler.as_ref())?;
        if let Some(installed) = approved.latest.get(name) {
            let skill =
                approved.load_active(name, services.store.as_ref(), services.compiler.as_ref())?;
            let authorization = if installed.snapshot.origin == SkillOrigin::Bundled {
                services.inventory
            } else {
                super::super::receipts::hash(&installed.operation_hash)?
            };
            let snapshot = SkillSnapshotV1::new(&skill, installed.snapshot.origin, authorization);
            return Ok(ResolvedSkill { skill, snapshot });
        }
        let package = services
            .bundled
            .get(name)
            .ok_or(super::super::SkillServiceError::NotInstalled)?;
        let skill = services.compiler.compile(package.clone())?;
        let snapshot = SkillSnapshotV1::new(&skill, SkillOrigin::Bundled, services.inventory);
        Ok(ResolvedSkill { skill, snapshot })
    }
    pub fn installed_skill_statuses(&self) -> Result<Vec<SkillStatus>, AppError> {
        let services = self
            .skills
            .as_ref()
            .ok_or(super::super::SkillServiceError::NotInstalled)?;
        let mut statuses =
            self.skill_statuses(services.store.as_ref(), services.compiler.as_ref())?;
        for name in services.bundled.keys() {
            if statuses.iter().any(|s| &s.name == name) {
                continue;
            }
            let skill = services.compiler.compile(services.bundled[name].clone())?;
            let screened = self.guard.screen(skill.metadata().description())?;
            let available = self.check_skill_content(&skill).is_ok();
            statuses.push(SkillStatus {
                name: name.clone(),
                version: skill.metadata().version().as_str().into(),
                sha256: crate::hex(skill.package().hash().as_bytes()),
                origin: SkillOrigin::Bundled,
                active: true,
                available,
                description: screened.text,
                warning: (!available)
                    .then(|| "Skill content was blocked; inspect it before use.".into()),
            });
        }
        statuses.sort_by(|a, b| a.name.cmp(&b.name));
        if statuses.iter().filter(|s| s.active).count() > 32 {
            return Err(super::super::SkillServiceError::ActiveLimit.into());
        }
        Ok(statuses)
    }
    pub fn skill_catalog_text(&self) -> Result<String, AppError> {
        if self.skills.is_none() {
            return Ok(String::new());
        }
        let statuses = self.installed_skill_statuses()?;
        let mut text = String::new();
        for status in statuses.into_iter().filter(|s| s.active && s.available) {
            text.push_str(status.name.as_str());
            text.push_str(": ");
            text.push_str(&status.description);
            text.push('\n');
        }
        Ok(self.guard.screen(&text)?.text)
    }
    pub fn skill_command_metadata(&self) -> Result<Vec<(String, String)>, AppError> {
        if self.skills.is_none() {
            return Ok(Vec::new());
        }
        Ok(self
            .installed_skill_statuses()?
            .into_iter()
            .filter(|s| s.active && s.available && self.skill_invocable(s.name.as_str()))
            .map(|s| (s.name.as_str().into(), s.description))
            .collect())
    }
    pub fn skill_invocable(&self, name: &str) -> bool {
        let Ok(name) = SkillName::parse(name) else {
            return false;
        };
        self.resolve_skill(&name)
            .is_ok_and(|s| s.skill.metadata().invocable())
    }
    pub fn inspect_skill(&self, name: &SkillName) -> Result<CompiledSkill, AppError> {
        let services = self
            .skills
            .as_ref()
            .ok_or(super::super::SkillServiceError::NotInstalled)?;
        let approved = self.approved_skills(services.compiler.as_ref())?;
        let skill = if let Some(installed) = approved.latest.get(name) {
            services.compiler.compile(installed.snapshot.package()?)?
        } else {
            services.compiler.compile(
                services
                    .bundled
                    .get(name)
                    .ok_or(super::super::SkillServiceError::NotInstalled)?
                    .clone(),
            )?
        };
        self.check_skill_content(&skill)?;
        Ok(skill)
    }
    pub fn set_bundled_skill_active(&self, name: &SkillName, active: bool) -> Result<(), AppError> {
        self.require_attended_analyst("change bundled skill activation")?;
        let services = self
            .skills
            .as_ref()
            .ok_or(super::super::SkillServiceError::NotInstalled)?;
        let package = services
            .bundled
            .get(name)
            .ok_or(super::super::SkillServiceError::NotInstalled)?;
        let skill = services.compiler.compile(package.clone())?;
        self.check_skill_content(&skill)?;
        let _lock = self.audit_log.lock_global_operations()?;
        let approved = self.approved_skills(services.compiler.as_ref())?;
        let mut snapshot = super::super::history::Snapshot::new(&skill, SkillOrigin::Bundled);
        snapshot.active = active;
        snapshot.previous_operation = approved.latest.get(name).map(|s| s.operation_hash.clone());
        self.commit_skill_snapshot(
            services.store.as_ref(),
            services.compiler.as_ref(),
            &snapshot,
        )?;
        Ok(())
    }
}
impl SkillServices {
    pub(crate) fn verifies_bundle(&self, skill: &CompiledSkill) -> bool {
        self.bundled.get(skill.metadata().name()) == Some(skill.package())
    }
}
