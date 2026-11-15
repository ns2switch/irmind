use super::{StartedSubagentPlan, TaskSession, invalid};
use crate::subagents::{BranchToolCall, SubagentRecord, SubagentTaskSpec, SubagentTypeSnapshotV1};
use crate::{AppError, CancellationToken, CaseId, Engine};

impl Engine<'_> {
    pub(super) async fn initialize_child_method(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        cancel: &CancellationToken,
    ) -> Result<bool, AppError> {
        let Some(expected) = task.skill_snapshot_sha256 else {
            return Ok(true);
        };
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let name = self
            .audit_log
            .entries(&case)?
            .iter()
            .filter(|entry| entry.kind == crate::AuditEventKind::SkillSnapshotV2)
            .map(|entry| crate::SkillSnapshotV2::decode(&entry.payload))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|snapshot| {
                snapshot
                    .identity()
                    .is_ok_and(|id| id.as_bytes() == expected.as_bytes())
            })
            .ok_or_else(invalid)?
            .name()?;
        let call = BranchToolCall {
            id: "initial_skill".into(),
            tool: "skill_read".into(),
            arguments: std::collections::BTreeMap::from([("name".into(), name.as_str().into())]),
        };
        state
            .messages
            .push(crate::CompletionMessage::assistant_tools(
                String::new(),
                vec![crate::ModelToolCall::from_proposal(
                    &call.id,
                    crate::ProposedCall {
                        tool: crate::Tool::SkillRead,
                        args: call.arguments.clone(),
                    },
                )?],
            ));
        self.execute_child_tools(started, task, state, vec![call], cancel)
            .await?;
        Ok(state.method.is_some())
    }

    pub(super) fn prepare_child_method(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        call: &BranchToolCall,
        cancel: &CancellationToken,
    ) -> Result<Box<crate::skills::runtime::PreparedSkillRead>, AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let _lock = self.repo.lock_case(&case)?;
        let batch = super::AgentBatch::new(self, &case, self.verifier.as_ref())?;
        batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        if cancel.is_cancelled() || self.clock.now()? >= task.deadline_at {
            return Err(AppError::Cancelled);
        }
        let name =
            irmind_domain::SkillName::parse(call.arguments.get("name").ok_or_else(invalid)?)?;
        let mut allowed = false;
        for kind in crate::subagents::bundled_subagent_types().map_err(|_| invalid())? {
            let snapshot = SubagentTypeSnapshotV1::new(&case, kind.id()).map_err(|_| invalid())?;
            if snapshot.identity().map_err(|_| invalid())? == task.type_snapshot_sha256 {
                allowed = kind.skills().iter().any(|item| item == name.as_str());
            }
        }
        if !allowed {
            return Err(invalid());
        }
        let resource = call
            .arguments
            .get("resource")
            .map_or("SKILL.md", String::as_str);
        let nonce = uuid::Uuid::parse_str(&task.nonce).map_err(|_| invalid())?;
        state.skills.read_limit = 16 * 1024;
        let prepared = self.prepare_skill_read(
            &case,
            &name,
            resource,
            &mut state.skills,
            (nonce, &call.id),
            cancel,
        )?;
        if state.method.is_none()
            && task.skill_snapshot_sha256.is_some_and(|expected| {
                !prepared
                    .receipt
                    .snapshot()
                    .is_ok_and(|actual| actual.as_bytes() == expected.as_bytes())
            })
        {
            return Err(invalid());
        }
        if cancel.is_cancelled() || self.clock.now()? > task.deadline_at {
            return Err(AppError::Cancelled);
        }
        Ok(Box::new(prepared))
    }
}
