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
        let _lock = self.repo.lock_case(case)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let _view = batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        if cancel.is_cancelled() || self.clock.now()? >= task.deadline_at {
            return Err(AppError::Cancelled);
        }
        let messages = state.messages.clone();
        let tools = self.child_read_catalog(started, task, state)?;
        let input = messages::canonical(&messages)?;
        let catalog_bytes = serde_json::to_vec(
            &tools
                .iter()
                .map(|tool| (&tool.name, &tool.parameters))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| invalid())?;
        let input_bound = (input.len() as u64)
            .checked_add(catalog_bytes.len() as u64)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(invalid)?;
        let available = task.budget.tokens.saturating_sub(state.usage.tokens);
        if input.len() > 48_000 || input_bound >= available {
            return Ok(None);
        }
        let output_limit = (available - input_bound).min(2048);
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
            request: CompletionRequest {
                messages,
                tools,
                max_output_tokens: u32::try_from(output_limit).map_err(|_| invalid())?,
                remaining_case_tokens: amount.tokens,
            },
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
        let outcome = self.child_model_outcome(task, step, response)?;
        let accounting = outcome
            .report
            .as_ref()
            .map(|report| {
                batch.push_payload(
                    crate::AuditEventKind::ModelUsage,
                    &serde_json::to_string(report).map_err(|_| invalid())?,
                    false,
                )
            })
            .transpose()?;
        state.usage = state
            .usage
            .checked_add(outcome.terminal.usage)
            .map_err(|_| invalid())?;
        state.summary = outcome.terminal.guarded_summary;
        let calls = outcome
            .reply
            .as_ref()
            .map(|reply| reply.tool_calls.clone())
            .unwrap_or_default();
        let done = outcome.reply.is_none() || calls.is_empty();
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
