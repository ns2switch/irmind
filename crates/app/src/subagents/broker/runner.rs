//! Single-child model transaction; tools are enabled by the bounded dispatcher.
use super::{AgentBatch, StartedSubagentPlan, invalid};
use crate::subagents::{
    SubagentBranchPayload, SubagentDigest, SubagentReservationV1, SubagentResultV1,
    SubagentTaskSpec,
};
use crate::{AppError, CancellationToken, CaseId, CompletionRequest, Engine, LlmPort};

mod messages;
mod model;
mod outcome;
mod protocol;
mod session;
mod tools;
use session::TaskSession;

enum ChildProgress {
    Done(Box<SubagentResultV1>),
    Tools(Vec<crate::subagents::BranchToolCall>),
}

struct ModelStep {
    reservation: SubagentReservationV1,
    request: CompletionRequest,
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
        let objective = self.guard.screen(&task.objective)?;
        if !objective.detections.is_empty() {
            return Err(invalid());
        }
        let mut state = TaskSession::new(task, &objective.text)?;
        loop {
            if state.round >= task.budget.rounds
                || cancel.is_cancelled()
                || self.clock.now()? >= task.deadline_at
            {
                let status = if cancel.is_cancelled() || self.clock.now()? >= task.deadline_at {
                    crate::subagents::SubagentStatus::Cancelled
                } else {
                    crate::subagents::SubagentStatus::Partial
                };
                state
                    .coverage
                    .insert("The task limit was reached; completed work is retained.".into());
                return self.finish_child_session(&case, started, task, &mut state, status);
            }
            let Some(step) =
                self.reserve_child_model(&case, started, task, model, &mut state, cancel)?
            else {
                state
                    .coverage
                    .insert("Insufficient task tokens remain for another model request.".into());
                return self.finish_child_session(
                    &case,
                    started,
                    task,
                    &mut state,
                    crate::subagents::SubagentStatus::Partial,
                );
            };
            let remaining = task.deadline_at.saturating_sub(self.clock.now()?).min(600);
            let task_cancel = cancel.child_token();
            let response = if remaining == 0 {
                Err(AppError::Cancelled)
            } else {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(AppError::Cancelled),
                    result = tokio::time::timeout(std::time::Duration::from_secs(remaining), async {
                        let stream = model.complete(step.request.clone(), &task_cancel).await?;
                        crate::collect_model_stream(stream, &task_cancel).await
                    }) => match result { Ok(response) => response, Err(_) => Err(AppError::Cancelled) },
                }
            };
            task_cancel.cancel();
            let progress =
                self.finish_child_model(&case, started, task, &step, &mut state, response)?;
            match progress {
                ChildProgress::Done(result) => return Ok(*result),
                ChildProgress::Tools(calls) => {
                    if !self
                        .execute_child_tools(started, task, &mut state, calls, cancel)
                        .await?
                    {
                        return self.finish_child_session(
                            &case,
                            started,
                            task,
                            &mut state,
                            crate::subagents::SubagentStatus::Partial,
                        );
                    }
                }
            }
        }
    }

    fn finish_child_session(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        status: crate::subagents::SubagentStatus,
    ) -> Result<SubagentResultV1, AppError> {
        let _lock = self.repo.lock_case(case)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let terminal = state.terminal(status);
        let entry = self.child_entry(
            started,
            task,
            state.seq + 1,
            state.previous,
            SubagentBranchPayload::Terminal(terminal.clone()),
        )?;
        let checkpoint = self.publish_child_prefix(
            case,
            &[entry],
            state.checkpoint_id()?,
            &mut batch,
            &CancellationToken::new(),
        )?;
        let result =
            SubagentResultV1::from_terminal(&checkpoint, &terminal).map_err(|_| invalid())?;
        batch.push(&result)?;
        batch.publish(&CancellationToken::new())?;
        Ok(result)
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
