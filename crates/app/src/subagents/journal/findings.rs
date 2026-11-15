use super::{SubagentDigest, SubagentJournal, SubagentRecordError};
use crate::{AuditEventKind, Finding, SignedEntry};

pub(super) struct FindingEffect {
    pub canonical_sha256: SubagentDigest,
    pub seq: u64,
    pub at: u64,
    pub decision: SubagentDigest,
}
impl SubagentJournal {
    pub(super) fn observe_finding(
        &mut self,
        entry: &SignedEntry,
    ) -> Result<(), SubagentRecordError> {
        if entry.kind != AuditEventKind::FindingProposed
            || self.agent.as_ref() != Some(&entry.actor)
            || !self.plans.values().any(super::PlanLedger::is_open)
        {
            return Ok(());
        }
        let finding: Finding =
            serde_json::from_str(&entry.payload).map_err(|_| SubagentRecordError)?;
        if serde_json::to_vec(&finding).map_err(|_| SubagentRecordError)?
            != entry.payload.as_bytes()
            || entry.evidence.as_deref() != Some(finding.evidence_hash.as_str())
        {
            return Err(SubagentRecordError);
        }
        let decision = *self
            .finding_dispatches
            .get(&finding.id)
            .ok_or(SubagentRecordError)?;
        let accounted = self.accounting.get(&decision).ok_or(SubagentRecordError)?;
        let attr = accounted.attribution.as_ref().ok_or(SubagentRecordError)?;
        if accounted.seq >= entry.seq
            || self.findings.len() >= 10_000
            || self
                .findings
                .insert(
                    attr.proposal_sha256,
                    FindingEffect {
                        canonical_sha256: SubagentDigest::from_bytes(crate::sha256(
                            entry.payload.as_bytes(),
                        )),
                        seq: entry.seq,
                        at: entry.at,
                        decision,
                    },
                )
                .is_some()
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
