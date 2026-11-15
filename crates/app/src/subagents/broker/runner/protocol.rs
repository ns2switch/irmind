use super::{AgentBatch, StartedSubagentPlan, invalid};
use crate::subagents::{
    CheckedBranchChunk, SubagentBranchBody, SubagentBranchEntry, SubagentBranchPayload,
    SubagentCheckpointV1,
};
use crate::subagents::{SubagentDigest, SubagentTaskSpec};
use crate::{AppError, CancellationToken, CaseId, Engine};
impl Engine<'_> {
    pub(in crate::subagents::broker) fn child_entry(
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

    pub(in crate::subagents::broker) fn publish_child_prefix(
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
