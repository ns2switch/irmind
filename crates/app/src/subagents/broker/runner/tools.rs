use super::{AgentBatch, StartedSubagentPlan, TaskSession, invalid};
use crate::subagents::{
    BranchToolCall, BranchToolProposal, ReservationAction, ReservationPurpose,
    ReservationTransition, SubagentBranchPayload, SubagentDigest, SubagentRecord,
    SubagentReservationV1, SubagentResources, SubagentTaskSpec, TaskDispatchAttribution,
    TaskEvidenceQuery, TaskEvidenceResult,
};
use crate::{AppError, CancellationToken, CaseId, Engine, GraphQueryFilter, Tool};

pub(super) mod approvals;
mod completion;
mod finding;
pub(super) mod indicators;
mod query;
mod remote;
mod worker;

enum ChildAction {
    Query(Box<TaskEvidenceQuery>),
    Remote(crate::AuthorizedCall),
    Method,
    Finding(Box<crate::Finding>),
}

enum ChildReadResponse {
    Evidence(TaskEvidenceResult),
    Remote {
        result: TaskEvidenceResult,
        admitted: Vec<SubagentDigest>,
    },
    Method(Box<crate::skills::runtime::PreparedSkillRead>),
}

struct ReadEffect {
    call: BranchToolCall,
    reservation: SubagentReservationV1,
    cloud: Option<SubagentReservationV1>,
    proposal: SubagentDigest,
    decision: SubagentDigest,
}
struct ReadTicket {
    effect: ReadEffect,
    view: crate::subagents::VerifiedTaskQueryView,
    action: ChildAction,
}
impl Engine<'_> {
    pub(super) fn child_read_catalog(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &TaskSession,
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
            .task_method_tools(
                started,
                task.task_id,
                &skills,
                services.compiler.as_ref(),
                state.method,
            )
            .map_err(|_| invalid())?;
        Ok(self
            .available_tools()
            .into_iter()
            .filter(|spec| {
                tools.contains(spec.name)
                    && (query::supported(spec.name)
                        || matches!(spec.name, "skill_read" | "case_add_finding")
                        || remote::supported(spec.name) && task.remote_scope.is_some())
                    || tools.contains(spec.name)
                        && spec.name == "ti_lookup_external"
                        && task.remote_scope.is_some()
                        && !state.observed.is_empty()
            })
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
        state.queued.extend(calls);
        while let Some(call) = state.queued.pop_front() {
            if !state.accept_call_id(&call.id)
                || !state.transfer_fits(&call, task.budget.cloud_bytes)
            {
                return Ok(false);
            }
            if state.seq > 4092 {
                state.coverage.insert("The 4096-entry task branch limit was reached; terminal capacity is retained and no further tool was executed.".into());
                return Ok(false);
            }
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
            if matches!(
                Tool::parse(&call.tool),
                Ok(Tool::ThreatIntelExternal | Tool::ObjectRead)
            ) {
                if self.queue_child_approval(started, task, state, &call, cancel)? {
                    return Ok(true);
                }
                if call.tool == Tool::ThreatIntelExternal.as_str() {
                    state.coverage.insert("The external lookup was not authorized for this task or its observed evidence.".into());
                    return Ok(false);
                }
            }
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
                action,
            } = ticket;
            let response = match action {
                ChildAction::Query(query) => self
                    .run_child_query(view, *query, task.deadline_at, cancel)
                    .await
                    .map(ChildReadResponse::Evidence),
                ChildAction::Remote(call) => {
                    self.run_child_remote(started, task, &effect, &call, cancel)
                        .await
                }
                ChildAction::Finding(finding) => self
                    .publish_child_finding(started, task, &effect, *finding, cancel)
                    .await
                    .map(ChildReadResponse::Evidence),
                ChildAction::Method => self
                    .prepare_child_method(started, task, state, &effect.call, cancel)
                    .map(ChildReadResponse::Method),
            };
            self.finish_child_read(started, task, state, &effect, response)?;
        }
        Ok(true)
    }

    fn permit_child_read(
        &self,
        view: &crate::subagents::VerifiedTaskQueryView,
        started: &StartedSubagentPlan,
        state: &TaskSession,
        proposal: &crate::ProposedCall,
    ) -> Result<Option<crate::AuthorizedCall>, AppError> {
        let rules = self.policy_for_case_unlocked(view.case())?;
        if rules
            .permits(
                &proposal.tool,
                usize::try_from(started.plan.usage.calls + state.usage.calls)
                    .map_err(|_| invalid())?,
            )
            .is_err()
        {
            return Ok(None);
        }
        let case = crate::Case {
            id: view.case().clone(),
            title: "Delegated task".into(),
            severity: crate::Severity::Low,
            scope: crate::subagents::queries::scope_text(&view.scope).map_err(|_| invalid())?,
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
        Ok(
            match irmind_domain::evaluate_tainted_with_rules(
                &case,
                tainted,
                1,
                self.mode,
                false,
                self.clock.now()?,
                &rules,
            ) {
                crate::Decision::Allow(call) => Some(call),
                _ => None,
            },
        )
    }

    fn checked_child_action(
        &self,
        case: &CaseId,
        task: &SubagentTaskSpec,
        call: &BranchToolCall,
        view: &crate::subagents::VerifiedTaskQueryView,
        proposal: &crate::ProposedCall,
        authorized: crate::AuthorizedCall,
    ) -> Result<Option<ChildAction>, AppError> {
        if remote::supported(&call.tool) {
            if task.remote_scope.is_none() || !self.permit_child_remote(&authorized)? {
                return Ok(None);
            }
            if authorized.tool() == &Tool::ObjectRead {
                self.child_listed_object(case, task, &authorized)?;
            }
            Ok(Some(ChildAction::Remote(authorized)))
        } else {
            Ok(query::checked(proposal, call, task.task_id, view).ok())
        }
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
        let allowed = self.child_read_catalog(started, task, state)?;
        if !allowed.iter().any(|spec| spec.name == call.tool) {
            return Ok(None);
        }
        let proposal = crate::ProposedCall {
            tool: Tool::parse(&call.tool).map_err(|_| invalid())?,
            args: call.arguments.clone(),
        };
        let Some(authorized) = self.permit_child_read(&view, started, state, &proposal)? else {
            return Ok(None);
        };
        let Some(action) =
            self.checked_child_action(case, task, call, &view, &proposal, authorized)?
        else {
            return Ok(None);
        };
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
        let cloud =
            Self::reserve_child_bytes(&mut batch, started, task, call, state.call, &checkpoint)?;
        let effect = ReadEffect {
            cloud,
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
        effect.remember_reservations(state);
        Ok(Some(ReadTicket {
            effect: ReadEffect { decision, ..effect },
            view,
            action,
        }))
    }
}

impl ReadEffect {
    fn remember_reservations(&self, state: &mut TaskSession) {
        state.reservations.insert(self.reservation.operation_id);
        if let Some(cloud) = &self.cloud {
            state.reservations.insert(cloud.operation_id);
        }
    }
    fn attribution(&self, task: &SubagentTaskSpec) -> Result<String, AppError> {
        let attribution = TaskDispatchAttribution {
            version: 1,
            tool: self.call.tool.clone(),
            reserved_bytes: self
                .cloud
                .as_ref()
                .map_or(0, |reservation| reservation.amount.cloud_bytes),
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
