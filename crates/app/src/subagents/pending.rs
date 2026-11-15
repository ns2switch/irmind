//! A signed task request cannot be resolved through the parent tool dispatcher.
use super::{
    BranchChunkRef, CheckedBranchChunk, SubagentBranchPayload, SubagentCheckpointV1,
    SubagentDigest, SubagentRecord,
};
use crate::{
    Actor, AppError, ApprovalRequest, AuditEventKind, AuditOrigin, CancellationToken, CaseId,
    Engine,
};

impl Engine<'_> {
    pub(in crate::subagents) fn task_pending_ids_unlocked(
        &self,
        case: &CaseId,
        task: SubagentDigest,
    ) -> Result<Vec<SubagentDigest>, AppError> {
        let entries = self.audit_log.entries(case)?;
        let requests = self.pending_requests_unlocked(&self.repo.get_case(case)?, &entries)?;
        let mut identities = Vec::new();
        for request in requests {
            let Some(previous) = entries
                .iter()
                .find(|entry| entry.seq.checked_add(1) == Some(request.decision_seq))
            else {
                continue;
            };
            if previous.kind != AuditEventKind::SubagentCheckpointV1 {
                continue;
            }
            let checkpoint: SubagentCheckpointV1 = super::journal::decode_entry(previous)
                .map_err(|_| AppError::InvalidChain(previous.seq))?;
            if checkpoint.task_id == task
                && self.task_pending_binding_unlocked(case, &request)? == Some(task)
            {
                identities.push(
                    SubagentDigest::parse(&request.id)
                        .map_err(|_| AppError::InvalidChain(request.decision_seq))?,
                );
            }
        }
        identities.sort();
        Ok(identities)
    }

    pub(crate) fn require_root_approval_unlocked(
        &self,
        case: &CaseId,
        request: &ApprovalRequest,
    ) -> Result<(), AppError> {
        if self.task_pending_binding_unlocked(case, request)?.is_some() {
            return Err(AppError::Policy("This approval belongs to a subagent task; resolve it through its active task session.".into()));
        }
        Ok(())
    }

    /// Returns an authenticated owner identity, never an execution lease.
    /// Missing live task state must not turn this request into a parent request.
    fn task_pending_binding_unlocked(
        &self,
        case: &CaseId,
        request: &ApprovalRequest,
    ) -> Result<Option<SubagentDigest>, AppError> {
        let invalid = || AppError::InvalidChain(request.decision_seq);
        let entries = self.audit_log.entries(case)?;
        let index = entries
            .iter()
            .position(|entry| entry.seq == request.decision_seq)
            .ok_or_else(invalid)?;
        let pending = &entries[index];
        if pending.kind != AuditEventKind::NeedsApproval {
            return Err(invalid());
        }
        if !matches!(pending.actor, Actor::Agent(_)) {
            return if pending.origin == AuditOrigin::Agent.as_str() {
                Err(invalid())
            } else {
                Ok(None)
            };
        }
        let previous = index
            .checked_sub(1)
            .and_then(|index| entries.get(index))
            .ok_or_else(invalid)?;
        if previous.kind != AuditEventKind::SubagentCheckpointV1 {
            return if pending.origin == AuditOrigin::Agent.as_str() {
                Err(invalid())
            } else {
                Ok(None)
            };
        }
        let checkpoint: SubagentCheckpointV1 =
            super::journal::decode_entry(previous).map_err(|_| invalid())?;
        let mut journal =
            super::SubagentJournal::for_verification(case.clone()).map_err(|_| invalid())?;
        for entry in &entries {
            journal.accept(entry, self.verifier.as_ref())?;
        }
        let (task, plan, allocation) = journal
            .check_task_pending_owner(&checkpoint, &pending.actor)
            .map_err(|_| invalid())?;
        let ports = self.subagents.as_ref().ok_or_else(|| {
            AppError::Policy(
                "The task branch store is required to resolve this subagent request.".into(),
            )
        })?;
        let reference = BranchChunkRef::new(checkpoint.chunk_sha256, checkpoint.chunk_bytes)
            .map_err(|_| invalid())?;
        let bytes = ports
            .branches
            .read(case, &reference, &CancellationToken::new())?;
        let key = self.verifier.trusted_public_key(&pending.actor)?;
        let chunk = CheckedBranchChunk::decode(bytes.as_bytes(), &key, self.verifier.as_ref())
            .map_err(|_| invalid())?;
        let entry = chunk.entries().last().ok_or_else(invalid)?;
        let SubagentBranchPayload::ToolProposal(proposal) = &entry.body.payload else {
            return Err(invalid());
        };
        if entry.body.task_id != checkpoint.task_id
            || entry.body.seq != checkpoint.last
            || entry.body.nonce != task.nonce
            || entry.body.turn_id != plan.turn_id
            || entry.body.case_id != plan.case_id
            || proposal.allocation_sha256 != allocation
            || proposal.tool != request.tool.as_str()
            || proposal.arguments != request.args
            || chunk
                .checkpoint(
                    checkpoint.previous_checkpoint,
                    checkpoint.admitted_sources.clone(),
                )
                .map_err(|_| invalid())?
                .canonical()
                .map_err(|_| invalid())?
                != checkpoint.canonical().map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        Ok(Some(checkpoint.task_id))
    }
}
