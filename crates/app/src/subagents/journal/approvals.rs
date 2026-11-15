//! Analyst decisions bind a prior task proposal checkpoint, never a future result.
use super::{SubagentDigest, SubagentJournal, SubagentRecordError};
use crate::{Actor, ApprovalRequest, AuditEventKind, Case, Engine, SignedEntry, Verifier};

pub(super) struct TaskApprovalReceipt {
    pub task: SubagentDigest,
    pub checkpoint_seq: u64,
    pub request: ApprovalRequest,
    pub decision: Option<(bool, u64)>,
}
impl SubagentJournal {
    pub(super) fn observe_task_approval(
        &mut self,
        entry: &SignedEntry,
        verifier: &dyn Verifier,
    ) -> Result<(), SubagentRecordError> {
        match entry.kind {
            AuditEventKind::NeedsApproval if self.agent.as_ref() == Some(&entry.actor) => {
                let (sequence, checkpoint) =
                    self.latest_checkpoint.as_ref().ok_or(SubagentRecordError)?;
                if sequence.checked_add(1) != Some(entry.seq) || checkpoint.terminal {
                    return Err(SubagentRecordError);
                }
                let (task, _, _) = self.check_task_pending_owner(checkpoint, &entry.actor)?;
                let task = task.task_id;
                let case = Case {
                    id: self.case.clone(),
                    title: "Task request".into(),
                    severity: crate::Severity::Low,
                    scope: crate::subagents::queries::scope_text(&self.scope)?,
                    sealed: false,
                };
                let request =
                    Engine::parse_pending_event(&case, entry).map_err(|_| SubagentRecordError)?;
                let identity = SubagentDigest::parse(&request.id)?;
                if self.task_approvals.len() >= 10_000
                    || self
                        .task_approvals
                        .insert(
                            identity,
                            TaskApprovalReceipt {
                                task,
                                checkpoint_seq: *sequence,
                                request,
                                decision: None,
                            },
                        )
                        .is_some()
                {
                    return Err(SubagentRecordError);
                }
            }
            AuditEventKind::ApprovalGranted | AuditEventKind::ApprovalDenied => {
                let value: crate::approvals::ApprovalEvent =
                    serde_json::from_str(&entry.payload).map_err(|_| SubagentRecordError)?;
                let Some(receipt) = self
                    .task_approvals
                    .get_mut(&SubagentDigest::parse(&value.id)?)
                else {
                    return Ok(());
                };
                let granted = entry.kind == AuditEventKind::ApprovalGranted;
                if value.version != 1
                    || entry.actor != Actor::Analyst
                    || value.executed
                    || receipt.decision.is_some()
                    || granted && value.reason.is_some()
                    || !granted
                        && value
                            .reason
                            .as_ref()
                            .is_none_or(|reason| reason.trim().is_empty() || reason.len() > 500)
                {
                    return Err(SubagentRecordError);
                }
                let mut challenge = receipt.request.challenge.clone();
                if !granted {
                    challenge.extend_from_slice(b"\0deny");
                }
                let key = verifier
                    .trusted_public_key(&Actor::Analyst)
                    .map_err(|_| SubagentRecordError)?;
                let signature = hex::decode(&value.signature).map_err(|_| SubagentRecordError)?;
                verifier
                    .verify(&key, &challenge, &signature)
                    .map_err(|_| SubagentRecordError)?;
                receipt.decision = Some((granted, entry.seq));
            }
            _ => {}
        }
        Ok(())
    }
}
