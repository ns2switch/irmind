//! Analyst intents are delivered to the existing task; never the parent dispatcher.
use crate::subagents::{SubagentDigest, SubagentJournal, runtime::approvals::TaskApprovalDecision};
use crate::{AppError, ApprovalRequest, Case, CaseId, Engine, ProposedCall};
use std::collections::BTreeMap;

impl Engine<'_> {
    pub(super) fn grant_live_task_approval(
        &self,
        id: &CaseId,
        request_id: &str,
    ) -> Result<Option<String>, AppError> {
        let _lock = self.repo.lock_case(id)?;
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        let request = self
            .pending_requests_unlocked(&case, &self.audit_log.entries(id)?)?
            .into_iter()
            .find(|request| request.id == request_id)
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyPendingApprovalNotFound,
            ))?;
        let Some(task) = self.task_pending_binding_unlocked(id, &request)? else {
            return Ok(None);
        };
        self.require_live_task_request(id, &request, task)?;
        let mut journal =
            SubagentJournal::for_verification(id.clone()).map_err(|_| unavailable())?;
        for entry in self.audit_log.entries(id)? {
            journal.accept(&entry, self.verifier.as_ref())?;
        }
        let scope = journal
            .pending_task_scope(task, &request.tool, &self.policy, self.clock.now()?)
            .map_err(|_| unavailable())?;
        let mut narrowed = case;
        narrowed.scope = scope;
        let authorized = self
            .record_request_resolution_unlocked(id, &narrowed, &request, None)?
            .ok_or_else(unavailable)?;
        let delivered = self.deliver_task_approval(
            id,
            request_id,
            task,
            TaskApprovalDecision::Granted(authorized),
        )?;
        Ok(Some(if delivered {
            "Approval recorded for the active subagent; the task will recheck its reservation before execution."
        } else {
            "Approval recorded, but the subagent session ended; no tool was executed."
        }.into()))
    }
    pub(super) fn edit_live_task_approval_unlocked(
        &self,
        id: &CaseId,
        case: &Case,
        request: &ApprovalRequest,
        task: SubagentDigest,
        new_args: BTreeMap<String, String>,
    ) -> Result<String, AppError> {
        self.require_live_task_request(id, request, task)?;
        let proposal = ProposedCall {
            tool: request.tool.clone(),
            args: new_args,
        };
        // Editing is not approval: the resumed task checks these arguments and
        // creates a fresh signed proposal/challenge before any effect.
        if proposal.args.len() > 64
            || proposal
                .args
                .iter()
                .any(|(key, value)| key.len() > 128 || value.len() > 100_000)
            || serde_json::to_vec(&proposal.args)
                .map_err(|_| unavailable())?
                .len()
                > 128 * 1024
        {
            return Err(AppError::Policy(
                "Edited task arguments exceed the request limits".into(),
            ));
        }
        self.record_request_resolution_unlocked(
            id,
            case,
            request,
            Some("Superseded by Analyst-edited task arguments"),
        )?;
        self.audit(
            id,
            crate::AuditOrigin::Analyst,
            crate::AuditEventKind::Proposal,
            &format!("{} {:?}", proposal.tool.as_str(), proposal.args),
            None,
        )?;
        let delivered = self.deliver_task_approval(
            id,
            &request.id,
            task,
            TaskApprovalDecision::Edited(proposal.args),
        )?;
        Ok(if delivered {
            "Edited task arguments recorded; a fresh policy decision is required."
        } else {
            "Edited arguments recorded, but the task ended; no tool was executed."
        }
        .into())
    }
    fn require_live_task_request(
        &self,
        id: &CaseId,
        request: &ApprovalRequest,
        task: SubagentDigest,
    ) -> Result<(), AppError> {
        if self.has_live_task_approval(id, &request.id, task)? {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
}
fn unavailable() -> AppError {
    AppError::Policy("This subagent approval has no active task session or its scope, policy or deadline changed; deny the request or start a new plan. No parent tool was executed.".into())
}
