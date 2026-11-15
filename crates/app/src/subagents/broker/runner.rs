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
mod parallel;
mod protocol;
mod retention;
mod session;
mod skills;
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
        let control = self.register_live_subagent(&case, started.plan.plan_id, task_id, cancel)?;
        let cancel = &control.token;
        match self
            .execute_child_session(started, task_id, model, cancel)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) => self
                .reconcile_subagent_task(
                    started,
                    task_id,
                    if cancel.is_cancelled() {
                        crate::subagents::SubagentStatus::Cancelled
                    } else {
                        crate::subagents::SubagentStatus::Error
                    },
                )
                .or(Err(error)),
        }
    }

    async fn execute_child_session(
        &self,
        started: &StartedSubagentPlan,
        task_id: SubagentDigest,
        model: &dyn LlmPort,
        cancel: &CancellationToken,
    ) -> Result<SubagentResultV1, AppError> {
        self.require_attended_analyst("run subagent task")?;
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let task = started.task(task_id)?;
        let Some(mut state) = self
            .initialize_parallel_child(started, task, cancel)
            .await?
        else {
            return self.reconcile_subagent_task(
                started,
                task.task_id,
                crate::subagents::SubagentStatus::Partial,
            );
        };
        loop {
            if state.pending.is_some() {
                if !self
                    .poll_child_approval(started, task, &mut state, cancel)
                    .await?
                {
                    return self.stop_child_session(&case, started, task, &mut state, cancel);
                }
                if state.pending.is_some() {
                    tokio::select! {biased;()=cancel.cancelled()=>{},()=tokio::time::sleep(std::time::Duration::from_millis(100))=>{}}
                    continue;
                }
            }
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
            let Some(progress) = self
                .single_child_step(&case, started, task, &mut state, model, cancel)
                .await?
            else {
                return self.finish_child_session(
                    &case,
                    started,
                    task,
                    &mut state,
                    crate::subagents::SubagentStatus::Partial,
                );
            };
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

    fn stop_child_session(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        cancel: &CancellationToken,
    ) -> Result<SubagentResultV1, AppError> {
        self.finish_child_session(
            case,
            started,
            task,
            state,
            if cancel.is_cancelled() {
                crate::subagents::SubagentStatus::Cancelled
            } else {
                crate::subagents::SubagentStatus::Partial
            },
        )
    }

    async fn single_child_step(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        model: &dyn LlmPort,
        cancel: &CancellationToken,
    ) -> Result<Option<ChildProgress>, AppError> {
        let Some(step) = self.reserve_child_model(case, started, task, model, state, cancel)?
        else {
            if state.seq <= 4093 {
                state
                    .coverage
                    .insert("Insufficient task tokens remain for another model request.".into());
            }
            return Ok(None);
        };
        let response = step
            .complete(
                model,
                task.deadline_at.saturating_sub(self.clock.now()?).min(600),
                cancel,
            )
            .await;
        self.finish_child_model(case, started, task, &step, state, response)
            .map(Some)
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
        state.pending_approvals = self.task_pending_ids_unlocked(case, task.task_id)?;
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
