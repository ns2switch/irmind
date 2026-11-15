use super::{SubagentDigest, SubagentRecord, SubagentRecordError, SubagentResources, codec};
use crate::AuditEventKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct SubagentSourceRef {
    pub hash: SubagentDigest,
    pub index: u64,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubagentStatus {
    Completed,
    Partial,
    Cancelled,
    Error,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentResultV1 {
    pub(super) format_version: u8,
    pub case_id: String,
    pub task_id: SubagentDigest,
    pub checkpoint_sha256: SubagentDigest,
    pub status: SubagentStatus,
    pub guarded_summary: String,
    pub summary_sha256: SubagentDigest,
    pub sources: Vec<SubagentSourceRef>,
    pub coverage: Vec<String>,
    pub usage: SubagentResources,
    pub pending_approvals: Vec<SubagentDigest>,
}
impl SubagentResultV1 {
    pub fn from_terminal(
        checkpoint: &SubagentCheckpointV1,
        terminal: &super::BranchTerminal,
    ) -> Result<Self, SubagentRecordError> {
        if !checkpoint.terminal {
            return Err(SubagentRecordError);
        }
        let value = Self {
            format_version: 1,
            case_id: checkpoint.case_id.clone(),
            task_id: checkpoint.task_id,
            checkpoint_sha256: checkpoint.identity()?,
            status: terminal.status,
            guarded_summary: terminal.guarded_summary.clone(),
            summary_sha256: terminal.summary_sha256,
            sources: terminal.sources.clone(),
            coverage: terminal.coverage.clone(),
            usage: terminal.usage,
            pending_approvals: terminal.pending_approvals.clone(),
        };
        value.validate()?;
        Ok(value)
    }
}
impl SubagentRecord for SubagentResultV1 {
    const KIND: AuditEventKind = AuditEventKind::SubagentResultV1;
    const DOMAIN: &'static [u8] = b"irmind-subagent-result-v1\0";
    fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::uuid(&self.case_id)?;
        self.usage.validate_usage()?;
        codec::sorted(&self.sources, 16_384)?;
        codec::sorted(&self.pending_approvals, 4096)?;
        if self.format_version != 1
            || self.guarded_summary.len() > 16 * 1024
            || self.summary_sha256.as_bytes() != &crate::sha256(self.guarded_summary.as_bytes())
            || (self.status == SubagentStatus::Completed && !self.pending_approvals.is_empty())
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentCheckpointV1 {
    pub(super) format_version: u8,
    pub case_id: String,
    pub task_id: SubagentDigest,
    pub first: u64,
    pub last: u64,
    pub count: u64,
    pub previous_checkpoint: Option<SubagentDigest>,
    pub entries_sha256: SubagentDigest,
    pub chunk_sha256: SubagentDigest,
    pub chunk_bytes: u64,
    pub admitted_sources: Vec<SubagentDigest>,
    pub terminal: bool,
}
impl SubagentRecord for SubagentCheckpointV1 {
    const KIND: AuditEventKind = AuditEventKind::SubagentCheckpointV1;
    const DOMAIN: &'static [u8] = b"irmind-subagent-checkpoint-v1\0";
    fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::uuid(&self.case_id)?;
        codec::sorted(&self.admitted_sources, 16_384)?;
        if self.format_version != 1
            || self.first == 0
            || self.last > 4096
            || self.count == 0
            || self.count > 64
            || self.chunk_bytes == 0
            || self.chunk_bytes > 1024 * 1024
            || self
                .last
                .checked_sub(self.first)
                .and_then(|n| n.checked_add(1))
                != Some(self.count)
            || self.previous_checkpoint.is_none() != (self.first == 1)
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
