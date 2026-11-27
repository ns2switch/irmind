use super::{
    SubagentPlanApprovalV1, SubagentPlanDecision, SubagentPlanV1, SubagentRecord,
    SubagentRecordError,
};
use crate::{Actor, AuditEventKind, SignedEntry, Verifier, hex, sha256};

/// Authenticate recorded consent. A fresh broker transaction must still recheck
/// the plan, policy, current consumption and other holds before admitting work.
pub fn verify_subagent_plan_consent(
    entry: &SignedEntry,
    plan: &(impl SubagentRecord + AsRef<SubagentPlanV1>),
    verifier: &dyn Verifier,
) -> Result<(), SubagentRecordError> {
    if entry.actor != Actor::Analyst
        || entry.case_id != plan.as_ref().case_id
        || entry.evidence.is_some()
        || entry.kind != AuditEventKind::SubagentPlanApprovalV1
        || entry.at > plan.as_ref().deadline_at
        || entry.hash != sha256(&entry.canonical())
        || verifier
            .trusted_public_key(&Actor::Analyst)
            .map_err(|_| SubagentRecordError)?
            != entry.public_key
    {
        return Err(SubagentRecordError);
    }
    verifier
        .verify(&entry.public_key, &entry.hash, &entry.sig)
        .map_err(|_| SubagentRecordError)?;
    let (label, encoded) = entry.payload.split_once(':').ok_or(SubagentRecordError)?;
    if label != AuditEventKind::SubagentPlanApprovalV1.as_str() || encoded.len() > 512 * 1024 {
        return Err(SubagentRecordError);
    }
    let raw = hex::decode(encoded).map_err(|_| SubagentRecordError)?;
    if hex(&raw) != encoded {
        return Err(SubagentRecordError);
    }
    let consent = SubagentPlanApprovalV1::decode(&raw)?;
    if consent.decision != SubagentPlanDecision::Approve || !consent.matches(plan)? {
        return Err(SubagentRecordError);
    }
    Ok(())
}
