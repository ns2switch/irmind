use super::{
    AgentBatch, ChildReadResponse, ReadEffect, StartedSubagentPlan, TaskSession, invalid, query,
};
use crate::subagents::{
    BranchToolResult, ReservationAction, ReservationPurpose, ReservationTransition,
    SubagentBranchPayload, SubagentRecord, SubagentReservationV1, SubagentResources,
    SubagentTaskSpec, TaskEvidenceResult,
};
use crate::{AppError, CancellationToken, CaseId, Engine};
mod sources;
impl Engine<'_> {
    pub(super) fn finish_child_read(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        effect: &ReadEffect,
        response: Result<ChildReadResponse, AppError>,
    ) -> Result<(), AppError> {
        let case = &CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let call = &effect.call;
        let _lock = self.repo.lock_case(case)?;
        let (response, method) = match response {
            Ok(ChildReadResponse::Method(method)) if self.clock.now()? <= task.deadline_at => (
                Ok(TaskEvidenceResult::Text(method.output.clone())),
                Some(method),
            ),
            Ok(ChildReadResponse::Evidence(value)) => (Ok(value), None),
            Ok(ChildReadResponse::Method(_)) | Err(AppError::Cancelled) => {
                (Err(AppError::Cancelled), None)
            }
            Err(error) => (Err(error), None),
        };
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let view = batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        let sources = match &response {
            Ok(response) => sources::references(response, &effect.call, &view)?,
            Err(_) => vec![],
        };
        let (payload, text) = self.child_read_payload(task, effect, response.as_ref())?;
        let (payload, sources) = sources::attach(payload, sources);
        if let Ok(TaskEvidenceResult::Original(record)) = &response {
            super::indicators::observe(self, state, record, &sources)?;
        }
        mark_partial_read(state, &payload, method.as_deref());
        let mut entries = Vec::new();
        if let Some(method) = &method {
            entries.push(self.child_entry(
                started,
                task,
                state.seq + 1,
                state.previous,
                SubagentBranchPayload::SkillLoad(method.receipt.encode()?),
            )?);
        }
        let prev = entries.last().map_or(state.previous, |entry| entry.hash);
        entries.push(self.child_entry(
            started,
            task,
            state.seq + entries.len() as u64 + 1,
            prev,
            payload,
        )?);
        let checkpoint = self.publish_child_prefix(
            case,
            &entries,
            state.checkpoint_id()?,
            &mut batch,
            &CancellationToken::new(),
        )?;
        let usage = SubagentResources {
            calls: 1,
            ..SubagentResources::default()
        };
        let settlement = effect.settlement(started, task, state.call, usage, &checkpoint)?;
        batch.push(&settlement)?;
        batch.publish(&CancellationToken::new())?;
        state.seq = entries.last().ok_or_else(invalid)?.body.seq;
        state.previous = entries.last().ok_or_else(invalid)?.hash;
        state.checkpoint = Some(checkpoint);
        if let Some(method) = method
            && let Some(active) = method.active
        {
            state.skills.active = Some(active);
            state.method = Some(method.receipt.snapshot()?);
        }
        state.usage = state.usage.checked_add(usage).map_err(|_| invalid())?;
        state.retain_sources(sources);
        state.tool_message(task, &call.id, &text)?;
        Ok(())
    }
    fn child_read_payload(
        &self,
        task: &SubagentTaskSpec,
        effect: &ReadEffect,
        response: Result<&TaskEvidenceResult, &AppError>,
    ) -> Result<(SubagentBranchPayload, String), AppError> {
        if self.clock.now()? > task.deadline_at {
            return Ok((
                SubagentBranchPayload::BudgetNotice(crate::subagents::BranchBudgetNotice {
                    resource: crate::subagents::BranchBudgetResource::Calls,
                    reserved: 1,
                    consumed: 1,
                    limit: task.budget.calls,
                    partial: true,
                }),
                "The query exceeded the task deadline; its late result was not accepted.".into(),
            ));
        }
        let (text, partial) = match response {
            Ok(value) => query::text(value)?,
            Err(_) => (
                "The restricted evidence query failed; no unrestricted fallback was used.".into(),
                true,
            ),
        };
        let screened = self.guard.screen(&text)?;
        let max = self.policy.max_model_result_bytes.min(16 * 1024);
        let truncated = screened.text.len() > max;
        let mut text = screened.text;
        text.truncate(text.floor_char_boundary(text.len().min(max)));
        let body = BranchToolResult {
            call_id: effect.call.id.clone(),
            proposal_sha256: effect.proposal,
            decision_audit_sha256: effect.decision,
            reservation_sha256: effect.reservation.identity().map_err(|_| invalid())?,
            guarded_text: text.clone(),
            sources: vec![],
            partial: partial || truncated,
        };
        Ok((SubagentBranchPayload::ToolResult(body), text))
    }
}
impl ReadEffect {
    fn settlement(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        ordinal: u64,
        usage: SubagentResources,
        checkpoint: &crate::subagents::SubagentCheckpointV1,
    ) -> Result<SubagentReservationV1, AppError> {
        SubagentReservationV1::prepare(
            &started.plan,
            Some(task.task_id),
            ordinal,
            ReservationAction::SettleRequest,
            ReservationPurpose::Tool,
            ReservationTransition {
                amount: usage,
                parent_operation: Some(self.reservation.operation_id),
                cause_sha256: checkpoint.identity().map_err(|_| invalid())?,
                accounting_audit_sha256: Some(self.decision),
            },
        )
        .map_err(|_| invalid())
    }
}
fn mark_partial_read(
    state: &mut TaskSession,
    payload: &SubagentBranchPayload,
    method: Option<&crate::skills::runtime::PreparedSkillRead>,
) {
    if method.is_some_and(|method| method.receipt.result() != crate::SkillLoadResult::Loaded)
        || matches!(payload, SubagentBranchPayload::ToolResult(value) if value.partial)
        || matches!(payload, SubagentBranchPayload::BudgetNotice(_))
    {
        state.partial = true;
        state
            .coverage
            .insert("A tool result was incomplete or unavailable.".into());
    }
}
