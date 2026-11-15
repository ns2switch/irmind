//! Single-child model transaction; tools are enabled by the bounded dispatcher.
use super::{AgentBatch, StartedSubagentPlan, invalid};
use crate::subagents::{
    BranchModelRequest, CheckedBranchChunk, ReservationAction, ReservationPurpose,
    ReservationTransition, SubagentBranchBody, SubagentBranchEntry, SubagentBranchPayload,
    SubagentCheckpointV1, SubagentDigest, SubagentRecord, SubagentReservationV1, SubagentResources,
    SubagentResultV1, SubagentTaskSpec,
};
use crate::{
    AppError, CancellationToken, CaseId, CompletionRequest, Engine, LlmPort, ModelResponse,
    ModelUsage,
};

mod messages;
mod outcome;

struct ModelStep {
    reservation: SubagentReservationV1,
    request: CompletionRequest,
    checkpoint: SubagentCheckpointV1,
    previous: SubagentDigest,
}

impl Engine<'_> {
    pub fn run_subagent_task(
        &self,
        started: &StartedSubagentPlan,
        task: SubagentDigest,
        model: &dyn LlmPort,
        cancel: &CancellationToken,
    ) -> Result<SubagentResultV1, AppError> {
        crate::run_async(self.execute_subagent_task(started, task, model, cancel))
    }

    /// Executes one child without recursion. A started plan remains reserved
    /// until its terminal children have been reconciled by the broker.
    pub async fn execute_subagent_task(
        &self,
        started: &StartedSubagentPlan,
        task_id: SubagentDigest,
        model: &dyn LlmPort,
        cancel: &CancellationToken,
    ) -> Result<SubagentResultV1, AppError> {
        self.require_attended_analyst("run subagent task")?;
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let task = started
            .plan
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .ok_or_else(invalid)?;
        let step = self.reserve_child_model(&case, started, task, model, cancel)?;
        let remaining = task.deadline_at.saturating_sub(self.clock.now()?).min(600);
        if remaining == 0 {
            return self.finish_child_model(&case, started, task, &step, Err(AppError::Cancelled));
        }
        let task_cancel = cancel.child_token();
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AppError::Cancelled),
            result = tokio::time::timeout(std::time::Duration::from_secs(remaining), async {
                let stream = model.complete(step.request.clone(), &task_cancel).await?;
                crate::collect_model_stream(stream, &task_cancel).await
            }) => match result { Ok(response) => response, Err(_) => Err(AppError::Cancelled) },
        };
        task_cancel.cancel();
        self.finish_child_model(&case, started, task, &step, response)
    }

    fn reserve_child_model(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        model: &dyn LlmPort,
        cancel: &CancellationToken,
    ) -> Result<ModelStep, AppError> {
        let _lock = self.repo.lock_case(case)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let view = batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        if cancel.is_cancelled() || self.clock.now()? >= task.deadline_at {
            return Err(AppError::Cancelled);
        }
        let nonce = uuid::Uuid::parse_str(&task.nonce).map_err(|_| invalid())?;
        let objective = self.guard.screen(&task.objective)?;
        if !objective.detections.is_empty() {
            return Err(invalid());
        }
        let messages = messages::initial(&objective.text, &nonce, view.source_set());
        let input = messages::canonical(&messages)?;
        let input_bound = (input.len() as u64).checked_add(512).ok_or_else(invalid)?;
        let output_limit = task
            .budget
            .tokens
            .checked_sub(input_bound)
            .ok_or_else(invalid)?
            .min(2048);
        if output_limit == 0 {
            return Err(invalid());
        }
        let amount = SubagentResources {
            tokens: input_bound + output_limit,
            rounds: 1,
            calls: 0,
            cloud_bytes: 0,
        };
        let reservation = SubagentReservationV1::prepare(
            &started.plan,
            Some(task.task_id),
            1,
            ReservationAction::ReserveRequest,
            ReservationPurpose::Model,
            ReservationTransition {
                amount,
                parent_operation: Some(started.allocation.operation_id),
                cause_sha256: started.entry_hash,
                accounting_audit_sha256: None,
            },
        )
        .map_err(|_| invalid())?;
        batch.push(&reservation)?;
        let body = SubagentBranchPayload::ModelRequest(BranchModelRequest {
            call_id: "model_1".into(),
            model: model.descriptor(),
            messages_sha256: SubagentDigest::from_bytes(crate::sha256(&input)),
            reservation_sha256: reservation.identity().map_err(|_| invalid())?,
            round: 1,
            output_limit,
        });
        let entry =
            self.child_entry(started, task, 1, SubagentDigest::from_bytes([0; 32]), body)?;
        let checkpoint = self.publish_child_prefix(
            case,
            std::slice::from_ref(&entry),
            None,
            &mut batch,
            cancel,
        )?;
        batch.publish(cancel)?;
        Ok(ModelStep {
            reservation,
            request: CompletionRequest {
                messages,
                tools: vec![],
                max_output_tokens: u32::try_from(output_limit).map_err(|_| invalid())?,
                remaining_case_tokens: amount.tokens,
            },
            checkpoint,
            previous: entry.hash,
        })
    }

    fn finish_child_model(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        step: &ModelStep,
        response: Result<(ModelResponse, Option<ModelUsage>), AppError>,
    ) -> Result<SubagentResultV1, AppError> {
        let _lock = self.repo.lock_case(case)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let mut entries = Vec::new();
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
        if let Some(reply) = outcome.reply {
            entries.push(self.child_entry(
                started,
                task,
                2,
                step.previous,
                SubagentBranchPayload::ModelReply(reply),
            )?);
        }
        let terminal = outcome.terminal;
        let previous = entries.last().map_or(step.previous, |entry| entry.hash);
        entries.push(self.child_entry(
            started,
            task,
            entries.len() as u64 + 2,
            previous,
            SubagentBranchPayload::Terminal(terminal.clone()),
        )?);
        let checkpoint = self.publish_child_prefix(
            case,
            &entries,
            Some(step.checkpoint.identity().map_err(|_| invalid())?),
            &mut batch,
            &CancellationToken::new(),
        )?;
        let settlement = SubagentReservationV1::prepare(
            &started.plan,
            Some(task.task_id),
            1,
            ReservationAction::SettleRequest,
            ReservationPurpose::Model,
            ReservationTransition {
                amount: terminal.usage,
                parent_operation: Some(step.reservation.operation_id),
                cause_sha256: checkpoint.identity().map_err(|_| invalid())?,
                accounting_audit_sha256: accounting,
            },
        )
        .map_err(|_| invalid())?;
        batch.push(&settlement)?;
        let result =
            SubagentResultV1::from_terminal(&checkpoint, &terminal).map_err(|_| invalid())?;
        batch.push(&result)?;
        batch.publish(&CancellationToken::new())?;
        Ok(result)
    }

    fn child_entry(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        seq: u64,
        prev: SubagentDigest,
        payload: SubagentBranchPayload,
    ) -> Result<SubagentBranchEntry, AppError> {
        let agent = &self.skills.as_ref().ok_or_else(invalid)?.agent;
        let at = self.clock.now()?;
        if at > task.deadline_at
            && !matches!(
                payload,
                SubagentBranchPayload::Terminal(_) | SubagentBranchPayload::BudgetNotice(_)
            )
        {
            return Err(AppError::Cancelled);
        }
        SubagentBranchEntry::sign(
            SubagentBranchBody {
                case_id: started.plan.case_id.clone(),
                turn_id: started.plan.turn_id.clone(),
                task_id: task.task_id,
                nonce: task.nonce.clone(),
                seq,
                at,
                payload,
                prev,
                public_key: SubagentDigest::parse(&crate::hex(&agent.public_key()))
                    .map_err(|_| invalid())?,
            },
            agent.as_ref(),
        )
        .map_err(|_| invalid())
    }

    fn publish_child_prefix(
        &self,
        case: &CaseId,
        entries: &[SubagentBranchEntry],
        previous: Option<SubagentDigest>,
        batch: &mut AgentBatch<'_>,
        cancel: &CancellationToken,
    ) -> Result<SubagentCheckpointV1, AppError> {
        let ports = self.subagents.as_ref().ok_or_else(invalid)?;
        let agent = &self.skills.as_ref().ok_or_else(invalid)?.agent;
        let chunk =
            CheckedBranchChunk::from_entries(entries, &agent.public_key(), self.verifier.as_ref())
                .map_err(|_| invalid())?;
        let published = ports
            .branches
            .publish(ports.branches.stage(case, &chunk, cancel)?)?;
        if published.case != *case
            || published.reference.hash() != chunk.hash()
            || published.reference.len() != chunk.bytes().len() as u64
        {
            return Err(invalid());
        }
        let checkpoint = chunk.checkpoint(previous, vec![]).map_err(|_| invalid())?;
        batch.push(&checkpoint)?;
        Ok(checkpoint)
    }
}

fn bounded_text(mut text: String) -> String {
    if text.len() > 16 * 1024 {
        let mut end = 16 * 1024;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}
