//! Provider work overlaps; admission and checkpoint commits retain plan order.
use super::{ChildProgress, ModelStep, StartedSubagentPlan, TaskSession, invalid};
use crate::subagents::{SubagentResultV1, SubagentStatus, SubagentTaskSpec};
use crate::{AppError, CancellationToken, CaseId, Engine, LlmPort};
use futures_util::{StreamExt, stream};

impl Engine<'_> {
    /// The execution cap is a trusted runtime setting, never a model argument.
    /// Results are returned in task ordinal order; the caller releases the plan.
    pub fn run_subagent_plan(
        &self,
        started: &StartedSubagentPlan,
        model: &dyn LlmPort,
        workers: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<SubagentResultV1>, AppError> {
        crate::run_async(self.execute_subagent_plan(started, model, workers, cancel))
    }

    pub async fn execute_subagent_plan(
        &self,
        started: &StartedSubagentPlan,
        model: &dyn LlmPort,
        workers: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<SubagentResultV1>, AppError> {
        self.require_attended_analyst("run subagent plan")?;
        if !(1..=8).contains(&workers) {
            return Err(invalid());
        }
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let controls = started
            .plan
            .tasks
            .iter()
            .map(|task| {
                self.register_live_subagent(&case, started.plan.plan_id, task.task_id, cancel)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut runs = self.initialize_parallel_plan(started, controls).await?;
        loop {
            let pending = self.prepare_parallel_wave(&case, started, model, &mut runs)?;
            if pending.is_empty() {
                break;
            }
            let responses = stream::iter(pending.iter().map(|(index, step)| async {
                let remaining = started.plan.tasks[*index]
                    .deadline_at
                    .saturating_sub(self.clock.now()?)
                    .min(600);
                step.complete(model, remaining, &runs.controls[*index].token)
                    .await
            }))
            .buffered(workers)
            .collect::<Vec<_>>()
            .await;
            // All provider futures have finished or been cancelled before any
            // failure reconciliation or tool effect begins.
            for ((index, step), response) in pending.into_iter().zip(responses) {
                let task = &started.plan.tasks[index];
                let state = runs.states[index].as_mut().ok_or_else(invalid)?;
                let signal = &runs.controls[index].token;
                let result = self
                    .commit_parallel_step(&case, started, task, state, (step, response), signal)
                    .await;
                let result = match result {
                    Ok(result) => result,
                    Err(_) => Some(self.reconcile_subagent_task(
                        started,
                        task.task_id,
                        if signal.is_cancelled() {
                            SubagentStatus::Cancelled
                        } else {
                            SubagentStatus::Error
                        },
                    )?),
                };
                runs.complete(index, result);
            }
        }
        runs.results
            .into_iter()
            .map(|result| result.ok_or_else(invalid))
            .collect()
    }

    async fn initialize_parallel_plan(
        &self,
        started: &StartedSubagentPlan,
        controls: Vec<crate::subagents::runtime::RunningTask>,
    ) -> Result<PlanSessions, AppError> {
        let mut runs = PlanSessions {
            controls,
            states: Vec::with_capacity(started.plan.tasks.len()),
            results: vec![None; started.plan.tasks.len()],
        };
        for (index, task) in started.plan.tasks.iter().enumerate() {
            let signal = &runs.controls[index].token;
            let initialized = self.initialize_parallel_child(started, task, signal).await;
            let result = match initialized {
                Ok(Some(state)) => {
                    runs.states.push(Some(state));
                    continue;
                }
                Ok(None) => {
                    self.reconcile_subagent_task(started, task.task_id, SubagentStatus::Partial)?
                }
                Err(_) => self.reconcile_subagent_task(
                    started,
                    task.task_id,
                    if signal.is_cancelled() {
                        SubagentStatus::Cancelled
                    } else {
                        SubagentStatus::Error
                    },
                )?,
            };
            runs.states.push(None);
            runs.complete(index, Some(result));
        }
        Ok(runs)
    }

    fn prepare_parallel_wave(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        model: &dyn LlmPort,
        runs: &mut PlanSessions,
    ) -> Result<Vec<(usize, ModelStep)>, AppError> {
        let mut pending = Vec::new();
        // Reserve in task ordinal order before polling provider futures.
        for index in 0..runs.states.len() {
            let Some(state) = &mut runs.states[index] else {
                continue;
            };
            let task = &started.plan.tasks[index];
            let signal = &runs.controls[index].token;
            let result = match self.prepare_parallel_step(case, started, task, model, state, signal)
            {
                Ok(Some(step)) => {
                    pending.push((index, step));
                    continue;
                }
                Ok(None) => {
                    let completion =
                        if signal.is_cancelled() || self.clock.now()? >= task.deadline_at {
                            SubagentStatus::Cancelled
                        } else {
                            SubagentStatus::Partial
                        };
                    self.finish_child_session(case, started, task, state, completion)?
                }
                Err(_) => {
                    self.reconcile_subagent_task(started, task.task_id, SubagentStatus::Error)?
                }
            };
            runs.complete(index, Some(result));
        }
        Ok(pending)
    }

    async fn commit_parallel_step(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        outcome: (
            ModelStep,
            Result<(crate::ModelResponse, Option<crate::ModelUsage>), AppError>,
        ),
        cancel: &CancellationToken,
    ) -> Result<Option<SubagentResultV1>, AppError> {
        match self.finish_child_model(case, started, task, &outcome.0, state, outcome.1)? {
            ChildProgress::Done(result) => Ok(Some(*result)),
            ChildProgress::Tools(calls) => {
                if self
                    .execute_child_tools(started, task, state, calls, cancel)
                    .await?
                {
                    Ok(None)
                } else {
                    self.finish_child_session(case, started, task, state, SubagentStatus::Partial)
                        .map(Some)
                }
            }
        }
    }

    async fn initialize_parallel_child(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        cancel: &CancellationToken,
    ) -> Result<Option<TaskSession>, AppError> {
        let objective = self.guard.screen(&task.objective)?;
        if !objective.detections.is_empty() {
            return Err(invalid());
        }
        let mut state = TaskSession::new(started, task, &objective.text)?;
        if !self
            .initialize_child_method(started, task, &mut state, cancel)
            .await?
        {
            return Ok(None);
        }
        Ok(Some(state))
    }

    fn prepare_parallel_step(
        &self,
        case: &CaseId,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        model: &dyn LlmPort,
        state: &mut TaskSession,
        cancel: &CancellationToken,
    ) -> Result<Option<ModelStep>, AppError> {
        if cancel.is_cancelled()
            || state.round >= task.budget.rounds
            || self.clock.now()? >= task.deadline_at
        {
            state
                .coverage
                .insert("The task limit was reached; completed work is retained.".into());
            return Ok(None);
        }
        self.reserve_child_model(case, started, task, model, state, cancel)
    }
}

struct PlanSessions {
    controls: Vec<crate::subagents::runtime::RunningTask>,
    states: Vec<Option<TaskSession>>,
    results: Vec<Option<SubagentResultV1>>,
}
impl PlanSessions {
    fn complete(&mut self, index: usize, result: Option<SubagentResultV1>) {
        if let Some(result) = result {
            self.results[index] = Some(result);
            self.states[index] = None;
        }
    }
}
