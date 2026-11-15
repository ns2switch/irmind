//! Live cancellation handles are process-local and never execution leases.
use super::SubagentDigest;
use crate::{AppError, CancellationToken, CaseId, Engine};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

type TaskKey = (String, SubagentDigest);
pub(crate) struct SubagentRuntime {
    pub(super) session: uuid::Uuid,
    tasks: Mutex<BTreeMap<TaskKey, LiveTask>>,
}
impl Default for SubagentRuntime {
    fn default() -> Self {
        Self {
            session: uuid::Uuid::new_v4(),
            tasks: Mutex::default(),
        }
    }
}
struct LiveTask {
    plan: SubagentDigest,
    token: CancellationToken,
    owner: uuid::Uuid,
}
pub(super) struct RunningTask {
    runtime: Arc<SubagentRuntime>,
    key: TaskKey,
    owner: uuid::Uuid,
    pub(super) token: CancellationToken,
}
impl Drop for RunningTask {
    fn drop(&mut self) {
        self.token.cancel();
        if let Ok(mut tasks) = self.runtime.tasks.lock()
            && tasks
                .get(&self.key)
                .is_some_and(|task| task.owner == self.owner)
        {
            tasks.remove(&self.key);
        }
    }
}
impl Engine<'_> {
    pub(super) fn register_live_subagent(
        &self,
        case: &CaseId,
        plan: SubagentDigest,
        task: SubagentDigest,
        parent: &CancellationToken,
    ) -> Result<RunningTask, AppError> {
        let key = (case.as_str().to_owned(), task);
        let mut tasks = self
            .subagent_runtime
            .tasks
            .lock()
            .map_err(|_| unavailable())?;
        if tasks.len() >= 256 || tasks.contains_key(&key) {
            return Err(unavailable());
        }
        let owner = uuid::Uuid::new_v4();
        let token = parent.child_token();
        tasks.insert(
            key.clone(),
            LiveTask {
                plan,
                token: token.clone(),
                owner,
            },
        );
        Ok(RunningTask {
            runtime: self.subagent_runtime.clone(),
            key,
            owner,
            token,
        })
    }
    /// A trusted Analyst cancellation intent, not an approval or effect retry.
    pub fn cancel_live_subagent_task(
        &self,
        case: &CaseId,
        task: SubagentDigest,
    ) -> Result<bool, AppError> {
        self.require_attended_analyst("cancel live subagent task")?;
        let tasks = self
            .subagent_runtime
            .tasks
            .lock()
            .map_err(|_| unavailable())?;
        let Some(task) = tasks.get(&(case.as_str().to_owned(), task)) else {
            return Ok(false);
        };
        task.token.cancel();
        Ok(true)
    }
    pub fn cancel_live_subagent_plan(
        &self,
        case: &CaseId,
        plan: SubagentDigest,
    ) -> Result<usize, AppError> {
        self.require_attended_analyst("cancel live subagent plan")?;
        let tasks = self
            .subagent_runtime
            .tasks
            .lock()
            .map_err(|_| unavailable())?;
        let mut count = 0;
        for ((owner, _), task) in tasks.iter() {
            if owner == case.as_str() && task.plan == plan {
                task.token.cancel();
                count += 1;
            }
        }
        Ok(count)
    }
    pub(super) fn has_live_subagents(&self, case: &CaseId) -> Result<bool, AppError> {
        let tasks = self
            .subagent_runtime
            .tasks
            .lock()
            .map_err(|_| unavailable())?;
        Ok(tasks.keys().any(|(owner, _)| owner == case.as_str()))
    }
}
fn unavailable() -> AppError {
    AppError::Policy("The subagent task is already running or its session is unavailable".into())
}
