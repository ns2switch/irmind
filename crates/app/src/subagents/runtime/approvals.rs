//! Live delivery is separate from durable ownership and cannot replay an effect.
use super::{SubagentRuntime, unavailable};
use crate::subagents::SubagentDigest;
use crate::{AppError, AuthorizedCall, CancellationToken, CaseId, Engine};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::oneshot;

pub(crate) enum TaskApprovalDecision {
    Granted(AuthorizedCall),
    Denied,
    Edited(BTreeMap<String, String>),
}
pub(super) struct LiveApproval {
    task: SubagentDigest,
    owner: uuid::Uuid,
    registration: uuid::Uuid,
    reply: oneshot::Sender<TaskApprovalDecision>,
}
pub(in crate::subagents) struct ApprovalWait {
    runtime: Arc<SubagentRuntime>,
    key: (String, String),
    registration: uuid::Uuid,
    pub receiver: oneshot::Receiver<TaskApprovalDecision>,
    pub expires: std::time::Instant,
}
impl Drop for ApprovalWait {
    fn drop(&mut self) {
        if let Ok(mut approvals) = self.runtime.approvals.lock()
            && approvals
                .get(&self.key)
                .is_some_and(|pending| pending.registration == self.registration)
        {
            approvals.remove(&self.key);
        }
    }
}
impl Engine<'_> {
    pub(in crate::subagents) fn register_task_approval(
        &self,
        case: &CaseId,
        task: SubagentDigest,
        request: &str,
        deadline: u64,
        cancel: &CancellationToken,
    ) -> Result<ApprovalWait, AppError> {
        let tasks = self
            .subagent_runtime
            .tasks
            .lock()
            .map_err(|_| unavailable())?;
        let live = tasks
            .get(&(case.as_str().into(), task))
            .ok_or_else(unavailable)?;
        if live.token.is_cancelled() || cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let remaining = deadline.saturating_sub(self.clock.now()?).min(600);
        if remaining == 0 {
            return Err(AppError::Cancelled);
        }
        let key = (case.as_str().into(), request.into());
        let mut approvals = self
            .subagent_runtime
            .approvals
            .lock()
            .map_err(|_| unavailable())?;
        if approvals.len() >= 256 || approvals.contains_key(&key) {
            return Err(unavailable());
        }
        let (reply, receiver) = oneshot::channel();
        let registration = uuid::Uuid::new_v4();
        approvals.insert(
            key.clone(),
            LiveApproval {
                task,
                owner: live.owner,
                registration,
                reply,
            },
        );
        Ok(ApprovalWait {
            runtime: self.subagent_runtime.clone(),
            key,
            registration,
            receiver,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(remaining),
        })
    }
    pub(crate) fn has_live_task_approval(
        &self,
        case: &CaseId,
        request: &str,
        task: SubagentDigest,
    ) -> Result<bool, AppError> {
        self.live_task_approval_identity(case, request, task)
            .map(|identity| identity.is_some())
    }

    pub(crate) fn live_task_approval_identity(
        &self,
        case: &CaseId,
        request: &str,
        task: SubagentDigest,
    ) -> Result<Option<(uuid::Uuid, uuid::Uuid)>, AppError> {
        let tasks = self
            .subagent_runtime
            .tasks
            .lock()
            .map_err(|_| unavailable())?;
        let Some(live) = tasks.get(&(case.as_str().into(), task)) else {
            return Ok(None);
        };
        if live.token.is_cancelled() {
            return Ok(None);
        }
        let approvals = self
            .subagent_runtime
            .approvals
            .lock()
            .map_err(|_| unavailable())?;
        Ok(approvals
            .get(&(case.as_str().into(), request.into()))
            .filter(|pending| {
                pending.task == task && pending.owner == live.owner && !pending.reply.is_closed()
            })
            .map(|pending| (pending.owner, pending.registration)))
    }

    pub(crate) fn deliver_task_approval(
        &self,
        case: &CaseId,
        request: &str,
        task: SubagentDigest,
        choice: TaskApprovalDecision,
    ) -> Result<bool, AppError> {
        let tasks = self
            .subagent_runtime
            .tasks
            .lock()
            .map_err(|_| unavailable())?;
        let Some(live) = tasks.get(&(case.as_str().into(), task)) else {
            return Ok(false);
        };
        if live.token.is_cancelled() {
            return Ok(false);
        }
        let mut approvals = self
            .subagent_runtime
            .approvals
            .lock()
            .map_err(|_| unavailable())?;
        let key = (case.as_str().into(), request.into());
        if approvals
            .get(&key)
            .is_none_or(|pending| pending.task != task || pending.owner != live.owner)
        {
            return Ok(false);
        }
        let pending = approvals.remove(&key).ok_or_else(unavailable)?;
        Ok(pending.reply.send(choice).is_ok())
    }
}
