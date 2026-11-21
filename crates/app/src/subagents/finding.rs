//! Pure reconstruction of a delegated, unconfirmed finding from its proposal.
use super::{BranchToolCall, SubagentDigest, SubagentRecordError};
use crate::{EntityDetails, Finding, FindingKind};
use std::collections::BTreeSet;

pub(super) fn proposed_finding(
    task: SubagentDigest,
    call: &BranchToolCall,
    sources: &BTreeSet<String>,
) -> Result<Finding, SubagentRecordError> {
    if call.tool != crate::Tool::CaseAddFinding.as_str() {
        return Err(SubagentRecordError);
    }
    let field = |name: &str| call.arguments.get(name).ok_or(SubagentRecordError);
    let kind = FindingKind::parse(field("kind")?).map_err(|_| SubagentRecordError)?;
    let details =
        EntityDetails::from_args(kind, &call.arguments).map_err(|_| SubagentRecordError)?;
    let finding = Finding {
        id: finding_id(task, &call.id),
        kind,
        value: field("value")?.clone(),
        evidence_hash: field("evidence_hash")?.clone(),
        confirmed: false,
        dismissed: false,
        source_query_limited: false,
        details,
    };
    if finding.value.trim().is_empty()
        || finding.value.len() > 2000
        || finding.value.contains('\0')
        || !finding.valid_for(sources)
    {
        return Err(SubagentRecordError);
    }
    Ok(finding)
}

pub(super) fn finding_id(task: SubagentDigest, call: &str) -> String {
    let mut bytes = b"irmind-subagent-finding-id-v1\0".to_vec();
    bytes.extend_from_slice(task.as_bytes());
    bytes.extend_from_slice(&(call.len() as u64).to_be_bytes());
    bytes.extend_from_slice(call.as_bytes());
    let digest = crate::sha256(&bytes);
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    uuid::Uuid::from_bytes(id).to_string()
}
