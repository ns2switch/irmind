use super::{AgentBatch, ReadEffect, StartedSubagentPlan, invalid};
use crate::subagents::{SubagentTaskSpec, TaskEvidenceQuery, TaskEvidenceResult};
use crate::{AppError, CancellationToken, CaseId, Engine};

impl Engine<'_> {
    pub(super) async fn publish_child_finding(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        effect: &ReadEffect,
        finding: crate::Finding,
        cancel: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        if let Some(crate::EntityDetails::Timeline {
            record_index: Some(index),
            ..
        }) = &finding.details
        {
            let query = TaskEvidenceQuery::RawRecords {
                hash: irmind_domain::EvidenceHash::parse(&finding.evidence_hash)
                    .map_err(|_| invalid())?,
                index: u64::try_from(*index).map_err(|_| invalid())?,
                original: false,
            };
            let batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
            let fresh = batch
                .journal
                .task_view(started, task.task_id, &self.policy)
                .map_err(|_| invalid())?;
            self.run_child_query(started, fresh, query, task.deadline_at, cancel)
                .await?;
        }
        let _lock = self.repo.lock_case(&case)?;
        if cancel.is_cancelled() || self.clock.now()? > task.deadline_at {
            return Err(AppError::Cancelled);
        }
        let mut batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
        let fresh = batch
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        let expected = crate::subagents::finding::proposed_finding(
            task.task_id,
            &effect.call,
            fresh.sources(),
        )
        .map_err(|_| invalid())?;
        let bytes = serde_json::to_string(&expected).map_err(|_| invalid())?;
        if bytes != serde_json::to_string(&finding).map_err(|_| invalid())? {
            return Err(invalid());
        }
        batch.push_evidenced_payload(
            crate::AuditEventKind::FindingProposed,
            &bytes,
            false,
            Some(&expected.evidence_hash),
        )?;
        batch.publish(cancel)?;
        Ok(TaskEvidenceResult::Text(format!(
            "Unconfirmed finding proposed: {}. Only the analyst can confirm it.",
            expected.id
        )))
    }
}
