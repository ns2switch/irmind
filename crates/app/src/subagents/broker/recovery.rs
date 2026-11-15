//! Close an interrupted task from its durable prefixes, without replaying effects.
use super::{AgentBatch, StartedSubagentPlan, invalid};
use crate::subagents::{
    BranchChunkRef, BranchTerminal, CheckedBranchChunk, ReservationAction, ReservationTransition,
    SubagentBranchPayload, SubagentDigest, SubagentRecord, SubagentReservationV1, SubagentResultV1,
    SubagentStatus,
};
use crate::{AppError, CancellationToken, CaseId, Engine};

impl Engine<'_> {
    /// Explicitly closes interrupted plans after a restart. No recovered value
    /// is exposed as an execution lease and no provider request is replayed.
    pub fn cancel_interrupted_subagent_plans(&self, case: &CaseId) -> Result<usize, AppError> {
        self.require_attended_analyst("close interrupted subagent plans")?;
        let recoveries = {
            let _lock = self.repo.lock_case(case)?;
            self.verify_unlocked(case)?;
            let mut journal = crate::subagents::SubagentJournal::for_verification(case.clone())
                .map_err(|_| invalid())?;
            for entry in self.audit_log.entries(case)? {
                journal.accept(&entry, self.verifier.as_ref())?;
            }
            journal.recovery_plans().map_err(|_| invalid())?
        };
        let mut closed = 0;
        for recovery in recoveries {
            if let Some(allocation) = recovery.allocation {
                let started = StartedSubagentPlan {
                    plan: recovery.plan,
                    entry_hash: recovery.entry_hash,
                    allocation,
                    // This private value is used solely for reconciliation.
                    skill_budget: std::sync::Arc::default(),
                };
                for task in &started.plan.tasks {
                    self.cancel_subagent_task(&started, task.task_id)?;
                }
                self.finish_subagent_plan(&started)?;
            } else {
                let _lock = self.repo.lock_case(case)?;
                let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
                if !batch
                    .journal
                    .plan_is_open(recovery.plan.identity().map_err(|_| invalid())?)
                    .map_err(|_| invalid())?
                {
                    continue;
                }
                let hold = super::plan_transition(
                    &recovery.plan,
                    ReservationAction::HoldPreview,
                    None,
                    recovery.entry_hash,
                )?;
                if recovery.needs_hold {
                    batch.push(&hold)?;
                }
                let expire = super::plan_transition(
                    &recovery.plan,
                    ReservationAction::ExpirePreview,
                    Some(hold.operation_id),
                    recovery.entry_hash,
                )?;
                batch.push(&expire)?;
                batch.publish(&CancellationToken::new())?;
            }
            closed += 1;
        }
        Ok(closed)
    }

    /// Cancellation does not authorize retries or free uncertain provider usage.
    /// The caller cancels and joins its worker before reconciling its task.
    pub fn cancel_subagent_task(
        &self,
        started: &StartedSubagentPlan,
        task: SubagentDigest,
    ) -> Result<SubagentResultV1, AppError> {
        self.reconcile_subagent_task(started, task, SubagentStatus::Cancelled)
    }

    pub(super) fn reconcile_subagent_task(
        &self,
        started: &StartedSubagentPlan,
        task_id: SubagentDigest,
        status: SubagentStatus,
    ) -> Result<SubagentResultV1, AppError> {
        self.require_attended_analyst("cancel subagent task")?;
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let _lock = self.repo.lock_case(&case)?;
        self.verify_unlocked(&case)?;
        let mut batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
        let recovery = batch
            .journal
            .task_recovery(started, task_id)
            .map_err(|_| invalid())?;
        if let Some(result) = recovery.completed {
            return Ok(result);
        }
        let task = started.task(task_id)?;
        let (mut terminal, seq, previous) =
            self.read_interrupted_prefix(&case, &recovery, status)?;
        terminal.pending_approvals = self.task_pending_ids_unlocked(&case, task_id)?;
        let cancel = CancellationToken::new();
        terminal.summary_sha256 =
            SubagentDigest::from_bytes(crate::sha256(terminal.guarded_summary.as_bytes()));
        let entry = self.child_entry(
            started,
            task,
            seq + 1,
            previous,
            SubagentBranchPayload::Terminal(terminal.clone()),
        )?;
        let prior = recovery
            .checkpoints
            .last()
            .map(SubagentRecord::identity)
            .transpose()
            .map_err(|_| invalid())?;
        let checkpoint = self.publish_child_prefix(&case, &[entry], prior, &mut batch, &cancel)?;
        let committed_prefix = checkpoint.identity().map_err(|_| invalid())?;
        for (request, accounting) in recovery.unsettled {
            let settlement = SubagentReservationV1::prepare(
                &started.plan,
                Some(task_id),
                request.request_ordinal,
                ReservationAction::SettleRequest,
                request.purpose,
                ReservationTransition {
                    amount: request.amount,
                    parent_operation: Some(request.operation_id),
                    cause_sha256: committed_prefix,
                    accounting_audit_sha256: accounting,
                },
            )
            .map_err(|_| invalid())?;
            batch.push(&settlement)?;
        }
        let result =
            SubagentResultV1::from_terminal(&checkpoint, &terminal).map_err(|_| invalid())?;
        batch.push(&result)?;
        batch.publish(&cancel)?;
        Ok(result)
    }
    fn read_interrupted_prefix(
        &self,
        case: &CaseId,
        recovery: &crate::subagents::journal::TaskRecovery,
        status: SubagentStatus,
    ) -> Result<(BranchTerminal, u64, SubagentDigest), AppError> {
        let mut terminal = interrupted_terminal(status, recovery);
        let cancel = CancellationToken::new();
        let ports = self.subagents.as_ref().ok_or_else(invalid)?;
        let agent = self.skills.as_ref().ok_or_else(invalid)?.agent.public_key();
        let mut previous = SubagentDigest::from_bytes([0; 32]);
        let mut seq = 0;
        for checkpoint in &recovery.checkpoints {
            let reference = BranchChunkRef::new(checkpoint.chunk_sha256, checkpoint.chunk_bytes)
                .map_err(|_| invalid())?;
            let bytes = ports.branches.read(case, &reference, &cancel)?;
            let chunk =
                CheckedBranchChunk::decode(bytes.as_bytes(), &agent, self.verifier.as_ref())
                    .map_err(|_| invalid())?;
            for entry in chunk.entries() {
                match &entry.body.payload {
                    SubagentBranchPayload::ModelReply(reply) => {
                        terminal.guarded_summary.clone_from(&reply.guarded_text);
                    }
                    SubagentBranchPayload::ToolResult(result) => {
                        terminal.sources.extend_from_slice(&result.sources);
                    }
                    SubagentBranchPayload::Terminal(_) => return Err(invalid()),
                    _ => {}
                }
                previous = entry.hash;
                seq = entry.body.seq;
            }
        }
        terminal.sources.sort();
        terminal.sources.dedup();
        Ok((terminal, seq, previous))
    }
}

fn interrupted_terminal(
    status: SubagentStatus,
    recovery: &crate::subagents::journal::TaskRecovery,
) -> BranchTerminal {
    BranchTerminal {
        status,
        guarded_summary:
            "The task stopped; committed work is retained and uncertain usage remains reserved."
                .into(),
        summary_sha256: SubagentDigest::from_bytes([0; 32]),
        sources: vec![],
        coverage: vec![
            "Interrupted task: no effects were retried; unavailable results are not inferred."
                .into(),
        ],
        usage: recovery.usage,
        reservation_ids: recovery.reservations.clone(),
        pending_approvals: vec![],
    }
}
