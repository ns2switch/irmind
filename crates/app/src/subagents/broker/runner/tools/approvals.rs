use super::{
    AgentBatch, AppError, CancellationToken, CaseId, Engine, ReadEffect, StartedSubagentPlan,
    TaskSession, invalid,
};
use crate::subagents::runtime::approvals::{ApprovalWait, TaskApprovalDecision};
use crate::subagents::{
    BranchToolCall, BranchToolProposal, ReservationAction, ReservationPurpose,
    ReservationTransition, SubagentBranchPayload, SubagentDigest, SubagentRecord,
    SubagentReservationV1, SubagentResources, SubagentTaskSpec, TaskEvidenceResult,
    TaskQueryPartialReason,
};
use crate::{Decision, ProposedCall, Tool};

pub(in crate::subagents::broker::runner) struct PendingChildTool {
    call: BranchToolCall,
    proposal: SubagentDigest,
    wait: ApprovalWait,
}
impl Engine<'_> {
    pub(super) fn queue_child_approval(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        call: &BranchToolCall,
        cancel: &CancellationToken,
    ) -> Result<bool, AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let _lock = self.repo.lock_case(&case)?;
        let mut batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
        let view = batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        if task.remote_scope.is_none()
            || matches!(view.scope, crate::CaseScope::LocalOnly)
            || !self
                .child_read_catalog(started, task, state)?
                .iter()
                .any(|spec| spec.name == call.tool)
        {
            return Ok(false);
        }
        let Some(observed) = call
            .arguments
            .get("ioc")
            .and_then(|value| state.observed.get(value))
        else {
            return Ok(false);
        };
        if !view
            .sources()
            .contains(&crate::hex(observed.source.hash.as_bytes()))
        {
            return Ok(false);
        }
        let Some(pending) = self.pending_child_lookup(&case, task, call)? else {
            return Ok(false);
        };
        let entry = self.child_entry(
            started,
            task,
            state.seq + 1,
            state.previous,
            SubagentBranchPayload::ToolProposal(BranchToolProposal {
                call_id: call.id.clone(),
                tool: call.tool.clone(),
                arguments: call.arguments.clone(),
                allocation_sha256: started.allocation.identity().map_err(|_| invalid())?,
                tainted: true,
                source: Some(observed.source),
                guarded_excerpt: observed.excerpt.clone(),
            }),
        )?;
        let checkpoint = self.publish_child_prefix(
            &case,
            std::slice::from_ref(&entry),
            state.checkpoint_id()?,
            &mut batch,
            cancel,
        )?;
        let request = crate::hex(&crate::sha256(&pending.challenge()));
        let wait =
            self.register_task_approval(&case, task.task_id, &request, task.deadline_at, cancel)?;
        batch.push_payload(
            crate::AuditEventKind::NeedsApproval,
            &pending_payload(&pending, call, &request)?,
            false,
        )?;
        batch.publish(cancel)?;
        state.seq = entry.body.seq;
        state.previous = entry.hash;
        state.checkpoint = Some(checkpoint);
        state.pending = Some(PendingChildTool {
            call: call.clone(),
            proposal: entry.hash,
            wait,
        });
        Ok(true)
    }
    fn pending_child_lookup(
        &self,
        case: &CaseId,
        task: &SubagentTaskSpec,
        call: &BranchToolCall,
    ) -> Result<Option<crate::PendingApproval>, AppError> {
        let proposal = ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: call.arguments.clone(),
        };
        let narrowed = crate::Case {
            id: case.clone(),
            title: "Delegated lookup".into(),
            severity: crate::Severity::Low,
            scope: task.remote_scope.clone().ok_or_else(invalid)?,
            sealed: false,
        };
        let rules = self.policy_for_case_unlocked(case)?;
        rules
            .permits(&proposal.tool, self.completed_calls_unlocked(case)?)
            .map_err(|_| invalid())?;
        let last = self.audit_log.last_entry(case)?.ok_or_else(invalid)?;
        let Decision::NeedsApproval(pending) = irmind_domain::evaluate_with_rules(
            &narrowed,
            proposal,
            last.seq.checked_add(2).ok_or_else(invalid)?,
            self.mode,
            self.clock.now()?,
            &rules,
        ) else {
            return Ok(None);
        };
        Ok(Some(pending))
    }
    pub(in crate::subagents::broker::runner) async fn poll_child_approval(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        cancel: &CancellationToken,
    ) -> Result<bool, AppError> {
        let Some(mut pending) = state.pending.take() else {
            return Ok(true);
        };
        if cancel.is_cancelled()
            || self.clock.now()? >= task.deadline_at
            || std::time::Instant::now() >= pending.wait.expires
        {
            self.child_approval_notice(
                started,
                task,
                state,
                &pending.call,
                "The pending lookup was cancelled or reached its deadline; it was not executed.",
            )?;
            return Ok(false);
        }
        let decision = match pending.wait.receiver.try_recv() {
            Ok(decision) => decision,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                state.pending = Some(pending);
                return Ok(true);
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                self.child_approval_notice(
                    started,
                    task,
                    state,
                    &pending.call,
                    "The Analyst decision channel closed; the tool was not executed.",
                )?;
                return Ok(false);
            }
        };
        match decision {
            TaskApprovalDecision::Denied => self.child_approval_notice(
                started,
                task,
                state,
                &pending.call,
                "The Analyst denied this external lookup; no request was sent.",
            )?,
            TaskApprovalDecision::Edited(args) => {
                if !state.queue_edited_call(&pending.call, args) {
                    return Ok(false);
                }
            }
            TaskApprovalDecision::Granted(call) => {
                let effect =
                    self.reserve_approved_child(started, task, state, &pending, &call, cancel)?;
                let remaining = task.deadline_at.saturating_sub(self.clock.now()?).min(600);
                let signal = cancel.child_token();
                let result = tokio::select! {biased;()=cancel.cancelled()=>Err(AppError::Cancelled),result=tokio::time::timeout(std::time::Duration::from_secs(remaining),self.run_authorized_tool(&call,false,&signal))=>result.unwrap_or(Err(AppError::Cancelled))};
                signal.cancel();
                let response = result
                    .and_then(|raw| {
                        self.retain_child_remote_result(started, task, &effect, &raw, cancel)
                    })
                    .map(super::ChildReadResponse::Evidence);
                self.finish_child_read(started, task, state, &effect, response)?;
            }
        }
        self.execute_child_tools(started, task, state, vec![], cancel)
            .await
    }
    fn reserve_approved_child(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        pending: &PendingChildTool,
        call: &crate::AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<ReadEffect, AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let _lock = self.repo.lock_case(&case)?;
        let mut batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
        batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        if call.case_id() != &case
            || call.tool().as_str() != pending.call.tool
            || call.proposal_args() != &pending.call.arguments
            || cancel.is_cancelled()
            || self.clock.now()? >= task.deadline_at
        {
            return Err(invalid());
        }
        state.call += 1;
        let reservation = SubagentReservationV1::prepare(
            &started.plan,
            Some(task.task_id),
            state.call,
            ReservationAction::ReserveRequest,
            ReservationPurpose::Tool,
            ReservationTransition {
                amount: SubagentResources {
                    calls: 1,
                    ..SubagentResources::default()
                },
                parent_operation: Some(started.allocation.operation_id),
                cause_sha256: state.checkpoint_id()?.ok_or_else(invalid)?,
                accounting_audit_sha256: None,
            },
        )
        .map_err(|_| invalid())?;
        batch.push(&reservation)?;
        let mut effect = ReadEffect {
            call: pending.call.clone(),
            reservation,
            proposal: pending.proposal,
            decision: SubagentDigest::from_bytes([0; 32]),
        };
        effect.decision = batch.push_payload(
            crate::AuditEventKind::ToolDispatch,
            &effect.attribution(task)?,
            false,
        )?;
        batch.publish(cancel)?;
        state.reservations.insert(effect.reservation.operation_id);
        Ok(effect)
    }
    fn retain_child_remote_result(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        effect: &ReadEffect,
        raw: &[u8],
        cancel: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        if raw.len() > 5_000_000 {
            return Err(AppError::RemoteTool);
        }
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let _lock = self.repo.lock_case(&case)?;
        if cancel.is_cancelled() || self.clock.now()? > task.deadline_at {
            return Err(AppError::Cancelled);
        }
        let mut batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
        batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        let hash = crate::hex(&crate::sha256(raw));
        self.evidence_store.put_evidence(&case, &hash, raw)?;
        batch.push_evidenced_payload(
            crate::AuditEventKind::ToolResult,
            &effect.attribution(task)?,
            false,
            Some(&hash),
        )?;
        batch.publish(cancel)?;
        Ok(TaskEvidenceResult::PartialText {
            text: format!(
                "Remote response retained as evidence {hash}. This adapter does not attest completeness.\n{}",
                String::from_utf8_lossy(&raw[..raw.len().min(16 * 1024)])
            ),
            reason: TaskQueryPartialReason::Coverage,
        })
    }
    fn child_approval_notice(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        call: &BranchToolCall,
        text: &str,
    ) -> Result<(), AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let _lock = self.repo.lock_case(&case)?;
        let mut batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
        let entry = self.child_entry(
            started,
            task,
            state.seq + 1,
            state.previous,
            SubagentBranchPayload::BudgetNotice(crate::subagents::BranchBudgetNotice {
                resource: crate::subagents::BranchBudgetResource::Calls,
                reserved: 0,
                consumed: 0,
                limit: task.budget.calls,
                partial: true,
            }),
        )?;
        let checkpoint = self.publish_child_prefix(
            &case,
            std::slice::from_ref(&entry),
            state.checkpoint_id()?,
            &mut batch,
            &CancellationToken::new(),
        )?;
        batch.publish(&CancellationToken::new())?;
        state.seq = entry.body.seq;
        state.previous = entry.hash;
        state.checkpoint = Some(checkpoint);
        state.partial = true;
        state.coverage.insert(text.into());
        state.tool_message(task, &call.id, text)
    }
}

fn pending_payload(
    pending: &crate::PendingApproval,
    call: &BranchToolCall,
    request: &str,
) -> Result<String, AppError> {
    serde_json::to_string(&crate::approvals::PendingEvent {
        version: 1,
        id: request.into(),
        mode: "attended".into(),
        decision_seq: pending.decision_seq(),
        tool: call.tool.clone(),
        args: call.arguments.clone(),
        challenge: crate::hex(&pending.challenge()),
    })
    .map_err(|_| invalid())
}
