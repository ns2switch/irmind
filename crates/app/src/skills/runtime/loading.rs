use super::{ResolvedSkill, SkillTurn};
use crate::{
    Actor, AppError, AuditEventKind, AuditOrigin, CaseId, Engine, ExecutionMode, SkillLoadResult,
    SkillLoadV1, SkillReadReceipt, SkillReceiptVerifier,
};
use irmind_domain::{SkillName, SkillResourcePath};
impl Engine<'_> {
    pub(crate) fn read_skill_local(
        &self,
        id: &CaseId,
        name: &SkillName,
        resource: &str,
        turn: &mut SkillTurn,
        nonce: uuid::Uuid,
        call: &str,
    ) -> Result<String, AppError> {
        let resolved = self.resolve_skill(name)?;
        SkillResourcePath::parse(resource)?;
        let package = resolved.skill.package();
        let original = package
            .resources()
            .values()
            .find(|r| r.path().as_str() == resource)
            .ok_or(super::super::SkillServiceError::NotInstalled)?
            .untrusted_text();
        let range = if resource == "SKILL.md" {
            resolved.skill.body_offset()..original.len()
        } else {
            0..original.len()
        };
        let snapshot = self.pin_skill_snapshot(id, &resolved)?;
        let mut result = SkillLoadResult::Loaded;
        let mut text = String::new();
        let mut detections = 0;
        if turn.reads >= 8 || (!turn.packages.contains(&snapshot) && turn.packages.len() >= 4) {
            result = SkillLoadResult::Limit;
        } else {
            let tainted = irmind_domain::TaintedSkillResource::new(
                name.clone(),
                resolved.skill.metadata().version().clone(),
                package,
                resource,
                range.clone(),
            )?;
            let screened = self.guard.screen(tainted.untrusted_text())?;
            detections = u32::try_from(screened.detections.len())
                .map_err(|_| super::super::receipts::invalid())?;
            if detections > 0 {
                result = SkillLoadResult::Blocked;
            } else if turn.bytes + screened.text.len() > 64 * 1024
                || screened.text.len() > turn.read_limit
            {
                result = SkillLoadResult::Limit;
            } else {
                text = screened.text;
            }
        }
        let receipt = SkillLoadV1::new(SkillReadReceipt {
            snapshot,
            turn: nonce,
            call,
            resource,
            range,
            guard: &self.guard.fingerprint(),
            text: text.clone(),
            detections,
            result,
        })?;
        self.audit_skill_load(id, &receipt)?;
        if matches!(result, SkillLoadResult::Loaded | SkillLoadResult::Blocked) {
            turn.reads += 1;
            turn.bytes += text.len();
            turn.packages.insert(snapshot);
        }
        if result == SkillLoadResult::Loaded {
            turn.active = Some(super::ActiveSkill {
                name: name.clone(),
                package: *package.hash(),
                tools: resolved.skill.metadata().tools().clone(),
            });
            Ok(format!(
                "Skill {} · version {} · package {} · resource {}\n{}",
                name.as_str(),
                resolved.skill.metadata().version().as_str(),
                crate::hex(package.hash().as_bytes()),
                resource,
                text
            ))
        } else {
            Ok(format!(
                "Skill content unavailable: {result:?}. No methodology was exposed."
            ))
        }
    }
    pub(crate) fn failed_skill_result(
        &self,
        id: &CaseId,
        error: &AppError,
    ) -> Result<String, AppError> {
        use crate::SkillServiceError::{ContentBlocked, NotInstalled, StorageMismatch};
        let kind = if matches!(
            error,
            AppError::SkillService(ContentBlocked | NotInstalled | StorageMismatch)
        ) {
            AuditEventKind::Denied
        } else {
            AuditEventKind::ToolError
        };
        self.audit(
            id,
            AuditOrigin::System,
            kind,
            "skill read failed; no methodology was exposed",
            None,
        )?;
        Ok(format!(
            "Skill read denied or unavailable: {error}. No methodology was exposed."
        ))
    }
    fn audit_skill_load(&self, id: &CaseId, receipt: &SkillLoadV1) -> Result<(), AppError> {
        let services = self
            .skills
            .as_ref()
            .ok_or(super::super::SkillServiceError::NotInstalled)?;
        let mut agent = self.local_handle();
        agent.signer = services.agent.clone();
        agent.mode = ExecutionMode::Unattended;
        agent.audit(
            id,
            AuditOrigin::Agent,
            AuditEventKind::SkillLoadV1,
            &receipt.encode()?,
            None,
        )?;
        Ok(())
    }
    fn pin_skill_snapshot(
        &self,
        id: &CaseId,
        resolved: &ResolvedSkill,
    ) -> Result<crate::SkillSnapshotId, AppError> {
        if self.signer.actor() != Actor::Analyst {
            return Err(super::super::receipts::invalid());
        }
        let services = self
            .skills
            .as_ref()
            .ok_or(super::super::SkillServiceError::NotInstalled)?;
        let entries = self.audit_log.entries(id)?;
        let identity = resolved.snapshot.identity()?;
        let mut state = SkillReceiptVerifier::default();
        for entry in &entries {
            state.accept(entry, services.compiler.as_ref())?;
        }
        if state
            .snapshots()
            .any(|s| s.identity().ok() == Some(identity))
        {
            return Ok(identity);
        }
        let entry = self.signed_entry(
            id,
            AuditOrigin::Analyst,
            AuditEventKind::SkillSnapshotV1,
            &resolved.snapshot.encode()?,
            None,
        )?;
        state.accept(&entry, services.compiler.as_ref())?;
        self.audit_log.append(&entry)?;
        Ok(identity)
    }
}
