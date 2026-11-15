//! Task-local admissions require an existing attributed main-chain source receipt.
use super::{SubagentDigest, SubagentJournal, SubagentRecord, SubagentRecordError};
use crate::subagents::{SubagentCheckpointV1, TaskDispatchAttribution};
use crate::{AuditEventKind, SignedEntry, Tool};

#[derive(Clone)]
pub(super) struct SourceEffect {
    pub source: SubagentDigest,
    pub seq: u64,
    pub decision: SubagentDigest,
    pub attribution: TaskDispatchAttribution,
}
impl SubagentJournal {
    pub(in crate::subagents) fn has_source_admissions(&self) -> bool {
        !self.checkpoint_admissions.is_empty()
    }
    pub(super) fn observe_source_effect(
        &mut self,
        entry: &SignedEntry,
    ) -> Result<(), SubagentRecordError> {
        if entry.kind != AuditEventKind::ToolResult
            || self.agent.as_ref() != Some(&entry.actor)
            || !entry.payload.starts_with('{')
        {
            return Ok(());
        }
        let attribution: TaskDispatchAttribution =
            serde_json::from_str(&entry.payload).map_err(|_| SubagentRecordError)?;
        if attribution.canonical()? != entry.payload.as_bytes() || !remote(&attribution.tool) {
            return Err(SubagentRecordError);
        }
        let source = SubagentDigest::parse(entry.evidence.as_deref().ok_or(SubagentRecordError)?)?;
        let decision = *self
            .request_dispatches
            .get(&attribution.proposal_sha256)
            .ok_or(SubagentRecordError)?;
        let dispatched = self.accounting.get(&decision).ok_or(SubagentRecordError)?;
        let original = dispatched.attribution.as_ref().ok_or(SubagentRecordError)?;
        if original.canonical()? != attribution.canonical()?
            || dispatched.seq >= entry.seq
            || !self.sources.contains(&source)
            || !self.indexed_sources.contains(&source)
        {
            return Err(SubagentRecordError);
        }
        let effects = self
            .source_effects
            .entry((attribution.task_id, source))
            .or_default();
        if effects.len() >= 10_000
            || effects
                .iter()
                .any(|effect| effect.attribution.proposal_sha256 == attribution.proposal_sha256)
        {
            return Err(SubagentRecordError);
        }
        effects.push(SourceEffect {
            source,
            seq: entry.seq,
            decision,
            attribution,
        });
        Ok(())
    }
    pub(super) fn validate_checkpoint_admissions(
        &mut self,
        checkpoint: &SubagentCheckpointV1,
        entry: &SignedEntry,
    ) -> Result<(), SubagentRecordError> {
        if checkpoint.admitted_sources.is_empty() {
            return Ok(());
        }
        let prior = checkpoint
            .previous_checkpoint
            .map(|id| {
                self.checkpoint_sequences
                    .get(&id)
                    .copied()
                    .ok_or(SubagentRecordError)
            })
            .transpose()?
            .unwrap_or(0);
        let task = self
            .plans
            .values()
            .flat_map(|plan| &plan.plan.tasks)
            .find(|task| task.task_id == checkpoint.task_id)
            .ok_or(SubagentRecordError)?;
        if task.remote_scope.is_none() || entry.at > task.deadline_at {
            return Err(SubagentRecordError);
        }
        let effects = checkpoint
            .admitted_sources
            .iter()
            .map(|hash| {
                self.source_effects
                    .get(&(checkpoint.task_id, *hash))
                    .and_then(|effects| {
                        effects
                            .iter()
                            .rev()
                            .find(|effect| effect.seq > prior && effect.seq < entry.seq)
                    })
                    .cloned()
                    .ok_or(SubagentRecordError)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self
            .checkpoint_admissions
            .insert(checkpoint.identity()?, effects)
            .is_some()
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}

fn remote(name: &str) -> bool {
    matches!(
        Tool::parse(name),
        Ok(Tool::SiemSearch
            | Tool::SiemGetAlert
            | Tool::CloudAuditEvents
            | Tool::CloudIdentity
            | Tool::EdrHostInfo
            | Tool::EdrProcessTree
            | Tool::EdrDetections
            | Tool::ThreatIntelInternal
            | Tool::ThreatIntelExternal
            | Tool::ObjectList
            | Tool::ObjectRead)
    )
}
