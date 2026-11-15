use super::{AgentBatch, StartedSubagentPlan, TaskSession, invalid};
use crate::subagents::{
    BranchToolCall, BranchToolProposal, BranchToolResult, ReservationAction, ReservationPurpose,
    ReservationTransition, SubagentBranchPayload, SubagentDigest, SubagentRecord,
    SubagentReservationV1, SubagentResources, SubagentTaskSpec, TaskDispatchAttribution,
    TaskEvidenceQuery, TaskEvidenceResult,
};
use crate::{AppError, CancellationToken, CaseId, Engine, GraphQueryFilter, Tool};

mod query;
mod worker;

struct ReadEffect {
    call: BranchToolCall,
    reservation: SubagentReservationV1,
    proposal: SubagentDigest,
    decision: SubagentDigest,
}
struct ReadTicket {
    effect: ReadEffect,
    view: crate::subagents::VerifiedTaskQueryView,
    query: TaskEvidenceQuery,
}
impl Engine<'_> {
    pub(super) fn child_read_catalog(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
    ) -> Result<Vec<crate::tool_catalog::ToolSpec>, AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
        let services = self.skills.as_ref().ok_or_else(invalid)?;
        let mut skills = crate::SkillReceiptVerifier::default();
        for entry in self.audit_log.entries(&case)? {
            skills.accept(&entry, services.compiler.as_ref())?;
        }
        let tools = batch
            .journal
            .task_method_tools(started, task.task_id, &skills, services.compiler.as_ref())
            .map_err(|_| invalid())?;
        Ok(self
            .available_tools()
            .into_iter()
            .filter(|spec| tools.contains(spec.name) && query::supported(spec.name))
            .collect())
    }

    pub(super) async fn execute_child_tools(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        calls: Vec<BranchToolCall>,
        cancel: &CancellationToken,
    ) -> Result<bool, AppError> {
        for call in calls {
            if cancel.is_cancelled()
                || self.clock.now()? >= task.deadline_at
                || state.usage.calls >= task.budget.calls
            {
                state
                    .coverage
                    .insert("A task limit prevented further tool execution.".into());
                return Ok(false);
            }
            let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
            let Some(ticket) =
                self.reserve_child_read(&case, started, task, state, &call, cancel)?
            else {
                state
                    .coverage
                    .insert("An unavailable or disallowed tool was not executed.".into());
                return Ok(false);
            };
            let ReadTicket {
                effect,
                view,
                query,
            } = ticket;
            let response = self
                .run_child_query(view, query, task.deadline_at, cancel)
                .await;
            self.finish_child_read(started, task, state, &effect, response)?;
        }
        Ok(true)
    }

    fn permit_child_read(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &TaskSession,
        proposal: &crate::ProposedCall,
    ) -> Result<bool, AppError> {
        let rules = self.policy_for_case_unlocked(case)?;
        if rules
            .permits(
                &proposal.tool,
                usize::try_from(started.plan.usage.calls + state.usage.calls)
                    .map_err(|_| invalid())?,
            )
            .is_err()
        {
            return Ok(false);
        }
        let case = crate::Case {
            id: case.clone(),
            title: "Delegated task".into(),
            severity: crate::Severity::Low,
            scope: task.remote_scope.clone().unwrap_or_else(|| "local".into()),
            sealed: false,
        };
        let tainted = irmind_domain::Tainted::from_external(
            proposal.clone(),
            irmind_domain::Provenance::new(
                crate::sha256(&serde_json::to_vec(&proposal.args).map_err(|_| invalid())?),
                None,
                irmind_domain::SourceKind::ModelProposal,
            ),
        );
        Ok(matches!(
            irmind_domain::evaluate_tainted_with_rules(
                &case,
                tainted,
                1,
                self.mode,
                false,
                self.clock.now()?,
                &rules
            ),
            crate::Decision::Allow(_)
        ))
    }

    fn reserve_child_read(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        call: &BranchToolCall,
        cancel: &CancellationToken,
    ) -> Result<Option<ReadTicket>, AppError> {
        let _lock = self.repo.lock_case(case)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let view = batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        let allowed = self.child_read_catalog(started, task)?;
        if !allowed.iter().any(|spec| spec.name == call.tool) {
            return Ok(None);
        }
        let proposal = crate::ProposedCall {
            tool: Tool::parse(&call.tool).map_err(|_| invalid())?,
            args: call.arguments.clone(),
        };
        if !self.permit_child_read(case, started, task, state, &proposal)? {
            return Ok(None);
        }
        let query = query::from_call(&proposal)?;
        query.validate(&view)?;
        let body = child_read_proposal(started, call)?;
        let entry = self.child_entry(
            started,
            task,
            state.seq + 1,
            state.previous,
            SubagentBranchPayload::ToolProposal(body),
        )?;
        let checkpoint = self.publish_child_prefix(
            case,
            std::slice::from_ref(&entry),
            state.checkpoint_id()?,
            &mut batch,
            cancel,
        )?;
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
                cause_sha256: checkpoint.identity().map_err(|_| invalid())?,
                accounting_audit_sha256: None,
            },
        )
        .map_err(|_| invalid())?;
        batch.push(&reservation)?;
        let effect = ReadEffect {
            call: call.clone(),
            reservation,
            proposal: entry.hash,
            decision: SubagentDigest::from_bytes([0; 32]),
        };
        let decision = batch.push_payload(
            crate::AuditEventKind::Allowed,
            &effect.attribution(task)?,
            false,
        )?;
        batch.publish(cancel)?;
        state.seq = entry.body.seq;
        state.previous = entry.hash;
        state.checkpoint = Some(checkpoint);
        state.reservations.insert(effect.reservation.operation_id);
        Ok(Some(ReadTicket {
            effect: ReadEffect { decision, ..effect },
            view,
            query,
        }))
    }

    fn finish_child_read(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        effect: &ReadEffect,
        response: Result<TaskEvidenceResult, AppError>,
    ) -> Result<(), AppError> {
        let case = &CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let call = &effect.call;
        let reservation = &effect.reservation;
        let decision = effect.decision;
        let _lock = self.repo.lock_case(case)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let (payload, text) = self.child_read_payload(task, effect, response)?;
        let entry = self.child_entry(started, task, state.seq + 1, state.previous, payload)?;
        let checkpoint = self.publish_child_prefix(
            case,
            std::slice::from_ref(&entry),
            state.checkpoint_id()?,
            &mut batch,
            &CancellationToken::new(),
        )?;
        let usage = SubagentResources {
            calls: 1,
            ..SubagentResources::default()
        };
        let settlement = SubagentReservationV1::prepare(
            &started.plan,
            Some(task.task_id),
            state.call,
            ReservationAction::SettleRequest,
            ReservationPurpose::Tool,
            ReservationTransition {
                amount: usage,
                parent_operation: Some(reservation.operation_id),
                cause_sha256: checkpoint.identity().map_err(|_| invalid())?,
                accounting_audit_sha256: Some(decision),
            },
        )
        .map_err(|_| invalid())?;
        batch.push(&settlement)?;
        batch.publish(&CancellationToken::new())?;
        state.seq = entry.body.seq;
        state.previous = entry.hash;
        state.checkpoint = Some(checkpoint);
        state.usage = state.usage.checked_add(usage).map_err(|_| invalid())?;
        state.tool_message(task, &call.id, &text)?;
        Ok(())
    }
    fn child_read_payload(
        &self,
        task: &SubagentTaskSpec,
        effect: &ReadEffect,
        response: Result<TaskEvidenceResult, AppError>,
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
            Ok(value) => (query::text(value)?, false),
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
    fn attribution(&self, task: &SubagentTaskSpec) -> Result<String, AppError> {
        let attribution = TaskDispatchAttribution {
            version: 1,
            tool: self.call.tool.clone(),
            reserved_bytes: 0,
            task_id: task.task_id,
            call_id: self.call.id.clone(),
            proposal_sha256: self.proposal,
            reservation_sha256: self.reservation.identity().map_err(|_| invalid())?,
            arguments_sha256: SubagentDigest::from_bytes(crate::sha256(
                &serde_json::to_vec(&self.call.arguments).map_err(|_| invalid())?,
            )),
            source_set_sha256: task.source_set_sha256,
        };
        String::from_utf8(attribution.canonical().map_err(|_| invalid())?).map_err(|_| invalid())
    }
}

fn child_read_proposal(
    started: &StartedSubagentPlan,
    call: &BranchToolCall,
) -> Result<BranchToolProposal, AppError> {
    Ok(BranchToolProposal {
        call_id: call.id.clone(),
        tool: call.tool.clone(),
        arguments: call.arguments.clone(),
        allocation_sha256: started.allocation.identity().map_err(|_| invalid())?,
        tainted: true,
        source: None,
        guarded_excerpt: String::new(),
    })
}
