use super::{AgentBatch, StartedSubagentPlan, TaskSession, invalid};
use super::{ChildProgress, ModelStep, messages};
use crate::subagents::{
    BranchModelRequest, ReservationAction, ReservationPurpose, ReservationTransition,
    SubagentBranchEntry, SubagentBranchPayload, SubagentReservationV1, SubagentResources,
    SubagentResultV1,
};
use crate::subagents::{SubagentDigest, SubagentRecord, SubagentTaskSpec};
use crate::{AppError, CancellationToken, CaseId, Engine};
use crate::{CompletionRequest, LlmPort, ModelResponse, ModelUsage};
impl Engine<'_> {
    pub(super) fn reserve_child_model(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        model: &dyn LlmPort,
        state: &mut TaskSession,
        cancel: &CancellationToken,
    ) -> Result<Option<ModelStep>, AppError> {
        if state.seq > 4093 {
            state.coverage.insert("The 4096-entry task branch limit was reached; no further model request was sent and terminal capacity is retained.".into());
            return Ok(None);
        }
        let _lock = self.repo.lock_case(case)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let view = batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        if cancel.is_cancelled() || self.clock.now()? >= task.deadline_at {
            return Err(AppError::Cancelled);
        }
        if state.round == 0 {
            messages::assigned_sources(&mut state.messages, task, &view)?;
        }
        let messages = state.messages.clone();
        let tools = if state.continuing {
            Vec::new()
        } else {
            self.child_read_catalog(started, task, state)?
        };
        let (input, input_bound) = messages::reserved_input(&messages, &tools)?;
        let available = task.budget.tokens.saturating_sub(state.usage.tokens);
        if input.len() > 48_000 || input_bound >= available {
            return Ok(None);
        }
        let Some(output_limit) = model_output_bound(model, state, input_bound, available) else {
            return Ok(None);
        };
        let amount = SubagentResources {
            tokens: input_bound + output_limit,
            rounds: 1,
            calls: 0,
            cloud_bytes: 0,
        };
        let reservation = SubagentReservationV1::prepare(
            &started.plan,
            Some(task.task_id),
            state.round + 1,
            ReservationAction::ReserveRequest,
            ReservationPurpose::Model,
            ReservationTransition {
                amount,
                parent_operation: Some(started.allocation.operation_id),
                cause_sha256: state.checkpoint_id()?.unwrap_or(started.entry_hash),
                accounting_audit_sha256: None,
            },
        )
        .map_err(|_| invalid())?;
        batch.push(&reservation)?;
        let body = SubagentBranchPayload::ModelRequest(BranchModelRequest {
            call_id: format!("model_{}", state.round + 1),
            model: model.descriptor(),
            messages_sha256: SubagentDigest::from_bytes(crate::sha256(&input)),
            reservation_sha256: reservation.identity().map_err(|_| invalid())?,
            round: state.round + 1,
            output_limit,
        });
        let entry = self.child_entry(started, task, state.seq + 1, state.previous, body)?;
        let checkpoint = self.publish_child_prefix(
            case,
            std::slice::from_ref(&entry),
            state.checkpoint_id()?,
            &mut batch,
            cancel,
        )?;
        batch.publish(cancel)?;
        state.round += 1;
        state.seq = entry.body.seq;
        state.previous = entry.hash;
        state.checkpoint = Some(checkpoint.clone());
        state.reservations.insert(reservation.operation_id);
        Ok(Some(ModelStep {
            reservation,
            request: CompletionRequest { messages, tools },
        }))
    }

    pub(super) fn finish_child_model(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        step: &ModelStep,
        state: &mut TaskSession,
        response: Result<(ModelResponse, Option<ModelUsage>), AppError>,
    ) -> Result<ChildProgress, AppError> {
        let _lock = self.repo.lock_case(case)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let mut outcome = self.child_model_outcome(task, step, response)?;
        let accounting = record_child_usage(&mut batch, outcome.report.as_ref())?;
        state.record_model_result(
            outcome.terminal.usage,
            std::mem::take(&mut outcome.terminal.guarded_summary),
            outcome.reply.as_ref().is_some_and(|reply| reply.truncated),
        )?;
        let continue_output = self.prepare_child_answer(started, task, state, &mut outcome)?;
        let calls = outcome
            .reply
            .as_ref()
            .map(|reply| reply.tool_calls.clone())
            .unwrap_or_default();
        let done = !continue_output
            && (outcome.reply.is_none()
                || calls.is_empty()
                || state.usage.tokens >= task.budget.tokens);
        let mut entries = Vec::new();
        if let Some(reply) = outcome.reply {
            entries.push(self.child_model_reply(started, task, state, reply)?);
        }
        if done {
            let prev = entries.last().map_or(state.previous, |entry| entry.hash);
            entries.push(self.child_entry(
                started,
                task,
                state.seq + entries.len() as u64 + 1,
                prev,
                SubagentBranchPayload::Terminal(state.terminal(outcome.terminal.status)),
            )?);
        }
        if continue_output {
            state.messages.push(crate::CompletionMessage::text(
                crate::MessageRole::System,
                crate::ports::model::output::CONTINUE_INSTRUCTION.into(),
            ));
        }
        let checkpoint = self.publish_child_prefix(
            case,
            &entries,
            state.checkpoint_id()?,
            &mut batch,
            &CancellationToken::new(),
        )?;
        let settlement = SubagentReservationV1::prepare(
            &started.plan,
            Some(task.task_id),
            state.round,
            ReservationAction::SettleRequest,
            ReservationPurpose::Model,
            ReservationTransition {
                amount: outcome.terminal.usage,
                parent_operation: Some(step.reservation.operation_id),
                cause_sha256: checkpoint.identity().map_err(|_| invalid())?,
                accounting_audit_sha256: accounting,
            },
        )
        .map_err(|_| invalid())?;
        batch.push(&settlement)?;
        let result = if done {
            let result = SubagentResultV1::from_terminal(
                &checkpoint,
                &state.terminal(outcome.terminal.status),
            )
            .map_err(|_| invalid())?;
            batch.push(&result)?;
            Some(result)
        } else {
            None
        };
        batch.publish(&CancellationToken::new())?;
        state.seq = entries.last().ok_or_else(invalid)?.body.seq;
        state.previous = entries.last().ok_or_else(invalid)?.hash;
        state.checkpoint = Some(checkpoint);
        Ok(match result {
            Some(result) => ChildProgress::Done(Box::new(result)),
            None => ChildProgress::Tools(calls),
        })
    }

    fn prepare_child_answer(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        outcome: &mut super::outcome::ModelOutcome,
    ) -> Result<bool, AppError> {
        if let Some(reply) = &mut outcome.reply {
            self.retain_child_reply(started, task, state, reply, &mut outcome.terminal.status)?;
        }
        let continue_output = outcome.reply.as_ref().is_some_and(|reply| {
            reply.truncated
                && !reply
                    .guarded_text
                    .ends_with(crate::ports::model::output::SECURITY_NOTICE)
        }) && state.continuations == 0
            && state.usage.tokens < task.budget.tokens;
        if continue_output {
            state.continuations += 1;
            state.continuing = true;
            state.coverage.insert("The model reached its maximum output. One automatic continuation is requested subject to the remaining reservation and rounds.".into());
        } else if state.continuing {
            state.continuing = false;
        }
        Ok(continue_output)
    }

    fn child_model_reply(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        reply: crate::subagents::BranchModelReply,
    ) -> Result<SubagentBranchEntry, AppError> {
        let calls = reply
            .tool_calls
            .iter()
            .map(|call| {
                crate::ModelToolCall::from_proposal(
                    &call.id,
                    crate::ProposedCall {
                        tool: crate::Tool::parse(&call.tool).map_err(|_| invalid())?,
                        args: call.arguments.clone(),
                    },
                )
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        state
            .messages
            .push(crate::CompletionMessage::assistant_tools(
                reply.guarded_text.clone(),
                calls,
            ));
        self.child_entry(
            started,
            task,
            state.seq + 1,
            state.previous,
            SubagentBranchPayload::ModelReply(reply),
        )
    }
}

impl ModelStep {
    pub(super) async fn complete(
        &self,
        model: &dyn LlmPort,
        remaining: u64,
        cancel: &CancellationToken,
    ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
        if remaining == 0 {
            return Err(AppError::Cancelled);
        }
        let task_cancel = cancel.child_token();
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AppError::Cancelled),
            result = tokio::time::timeout(std::time::Duration::from_secs(remaining), async {
                let stream = model.complete(self.request.clone(), &task_cancel).await?;
                crate::collect_model_stream(stream, &task_cancel).await
            }) => match result { Ok(response) => response, Err(_) => Err(AppError::Cancelled) },
        };
        task_cancel.cancel();
        response
    }
}

fn model_output_bound(
    model: &dyn LlmPort,
    state: &mut TaskSession,
    input_bound: u64,
    available: u64,
) -> Option<u64> {
    let Some(maximum) = model.output_profile().maximum_output_tokens else {
        state.coverage.insert("The model output maximum is unknown. Configure its native maximum in /settings model before running this subagent.".into());
        return None;
    };
    let output_limit = u64::from(maximum.get());
    if input_bound
        .checked_add(output_limit)
        .is_none_or(|required| required > available)
    {
        state.coverage.insert("The model maximum and input reservation do not fit the child token allocation. Review /budget and propose a plan with a sufficient child allocation.".into());
        return None;
    }
    Some(output_limit)
}

fn record_child_usage(
    batch: &mut AgentBatch<'_>,
    report: Option<&crate::UsageEvent>,
) -> Result<Option<SubagentDigest>, AppError> {
    report
        .map(|report| {
            batch.push_payload(
                crate::AuditEventKind::ModelUsage,
                &serde_json::to_string(report).map_err(|_| invalid())?,
                false,
            )
        })
        .transpose()
}
