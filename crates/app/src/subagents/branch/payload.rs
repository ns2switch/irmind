use crate::subagents::{
    SubagentDigest, SubagentRecordError, SubagentResources, SubagentSourceRef, SubagentStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchModelRequest {
    pub call_id: String,
    pub model: String,
    pub messages_sha256: SubagentDigest,
    pub reservation_sha256: SubagentDigest,
    pub round: u64,
    pub output_limit: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchToolCall {
    pub id: String,
    pub tool: String,
    pub arguments: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchModelReply {
    pub call_id: String,
    pub guarded_text: String,
    pub truncated: bool,
    pub tool_calls: Vec<BranchToolCall>,
    pub usage: Option<crate::ModelUsage>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchToolProposal {
    pub call_id: String,
    pub tool: String,
    pub arguments: BTreeMap<String, String>,
    pub allocation_sha256: SubagentDigest,
    pub tainted: bool,
    pub source: Option<SubagentSourceRef>,
    pub guarded_excerpt: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchToolResult {
    pub call_id: String,
    pub proposal_sha256: SubagentDigest,
    pub decision_audit_sha256: SubagentDigest,
    pub reservation_sha256: SubagentDigest,
    pub guarded_text: String,
    pub sources: Vec<SubagentSourceRef>,
    pub partial: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchCompaction {
    pub guarded_text: String,
    pub text_sha256: SubagentDigest,
    pub replaced_first: u64,
    pub replaced_last: u64,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchBudgetResource {
    Tokens,
    Calls,
    Rounds,
    CloudBytes,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchBudgetNotice {
    pub resource: BranchBudgetResource,
    pub reserved: u64,
    pub consumed: u64,
    pub limit: u64,
    pub partial: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchTerminal {
    pub status: SubagentStatus,
    pub guarded_summary: String,
    pub summary_sha256: SubagentDigest,
    pub sources: Vec<SubagentSourceRef>,
    pub coverage: Vec<String>,
    pub usage: SubagentResources,
    pub reservation_ids: Vec<SubagentDigest>,
    pub pending_approvals: Vec<SubagentDigest>,
}

#[derive(Clone, Debug)]
pub enum SubagentBranchPayload {
    ModelRequest(BranchModelRequest),
    ModelReply(BranchModelReply),
    ToolProposal(BranchToolProposal),
    ToolResult(BranchToolResult),
    SkillLoad(String),
    Compaction(BranchCompaction),
    BudgetNotice(BranchBudgetNotice),
    Terminal(BranchTerminal),
}
impl SubagentBranchPayload {
    pub const fn code(&self) -> u8 {
        match self {
            Self::ModelRequest(_) => 1,
            Self::ModelReply(_) => 2,
            Self::ToolProposal(_) => 3,
            Self::ToolResult(_) => 4,
            Self::SkillLoad(_) => 5,
            Self::Compaction(_) => 6,
            Self::BudgetNotice(_) => 7,
            Self::Terminal(_) => 8,
        }
    }
    pub(super) fn decode(code: u8, value: serde_json::Value) -> Result<Self, SubagentRecordError> {
        macro_rules! decode {
            ($kind:ident) => {
                serde_json::from_value(value)
                    .map(Self::$kind)
                    .map_err(|_| SubagentRecordError)
            };
        }
        match code {
            1 => decode!(ModelRequest),
            2 => decode!(ModelReply),
            3 => decode!(ToolProposal),
            4 => decode!(ToolResult),
            5 => decode!(SkillLoad),
            6 => decode!(Compaction),
            7 => decode!(BudgetNotice),
            8 => decode!(Terminal),
            _ => Err(SubagentRecordError),
        }
    }
    pub(super) fn validate(&self) -> Result<(), SubagentRecordError> {
        match self {
            Self::ModelRequest(v) => {
                call_id(&v.call_id)?;
                if v.model.is_empty()
                    || v.model.len() > 256
                    || v.round == 0
                    || v.round > 100
                    || v.output_limit == 0
                    || v.output_limit > 10_000_000
                {
                    return Err(SubagentRecordError);
                }
            }
            Self::ModelReply(v) => v.validate()?,
            Self::ToolProposal(v) => {
                call_id(&v.call_id)?;
                arguments(&v.tool, &v.arguments)?;
                if v.guarded_excerpt.len() > 16 * 1024 {
                    return Err(SubagentRecordError);
                }
            }
            Self::ToolResult(v) => {
                call_id(&v.call_id)?;
                super::super::codec::sorted(&v.sources, 16_384)?;
            }
            Self::SkillLoad(v) => {
                crate::SkillLoadV1::decode(v).map_err(|_| SubagentRecordError)?;
            }
            Self::Compaction(v) => {
                if v.replaced_first == 0
                    || v.replaced_last < v.replaced_first
                    || v.replaced_last > 4096
                    || v.text_sha256.as_bytes() != &crate::sha256(v.guarded_text.as_bytes())
                {
                    return Err(SubagentRecordError);
                }
            }
            Self::BudgetNotice(v) => {
                if v.reserved.checked_add(v.consumed).is_none() {
                    return Err(SubagentRecordError);
                }
                let max = match v.resource {
                    BranchBudgetResource::Tokens => 10_000_000,
                    BranchBudgetResource::Calls => 10_000,
                    BranchBudgetResource::Rounds => 100,
                    BranchBudgetResource::CloudBytes => 10_995_116_277_760,
                };
                if v.reserved > max || v.consumed > max || v.limit > max {
                    return Err(SubagentRecordError);
                }
            }
            Self::Terminal(v) => v.validate()?,
        }
        if serde_json::to_vec(self)
            .map_err(|_| SubagentRecordError)?
            .len()
            > 256 * 1024
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
impl Serialize for SubagentBranchPayload {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::ModelRequest(v) => v.serialize(s),
            Self::ModelReply(v) => v.serialize(s),
            Self::ToolProposal(v) => v.serialize(s),
            Self::ToolResult(v) => v.serialize(s),
            Self::SkillLoad(v) => v.serialize(s),
            Self::Compaction(v) => v.serialize(s),
            Self::BudgetNotice(v) => v.serialize(s),
            Self::Terminal(v) => v.serialize(s),
        }
    }
}
fn call_id(value: &str) -> Result<(), SubagentRecordError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
    {
        return Err(SubagentRecordError);
    }
    Ok(())
}
fn arguments(tool: &str, args: &BTreeMap<String, String>) -> Result<(), SubagentRecordError> {
    let parsed = crate::Tool::parse(tool).map_err(|_| SubagentRecordError)?;
    if parsed.as_str() != tool
        || args.len() > 64
        || args.iter().any(|(k, v)| k.len() > 128 || v.len() > 100_000)
    {
        return Err(SubagentRecordError);
    }
    Ok(())
}

impl BranchModelReply {
    fn validate(&self) -> Result<(), SubagentRecordError> {
        call_id(&self.call_id)?;
        if self.tool_calls.len() > 64 {
            return Err(SubagentRecordError);
        }
        let mut ids = std::collections::BTreeSet::new();
        for call in &self.tool_calls {
            call_id(&call.id)?;
            arguments(&call.tool, &call.arguments)?;
            if !ids.insert(&call.id) {
                return Err(SubagentRecordError);
            }
        }
        if let Some(usage) = self.usage
            && usage
                .input_tokens
                .checked_add(usage.output_tokens)
                .is_none_or(|n| n > 10_000_000)
        {
            return Err(SubagentRecordError);
        }

        Ok(())
    }
}

impl BranchTerminal {
    fn validate(&self) -> Result<(), SubagentRecordError> {
        self.usage.validate()?;
        super::super::codec::sorted(&self.sources, 16_384)?;
        super::super::codec::sorted(&self.reservation_ids, 4096)?;
        super::super::codec::sorted(&self.pending_approvals, 4096)?;
        if self.guarded_summary.len() > 16 * 1024
            || self.summary_sha256.as_bytes() != &crate::sha256(self.guarded_summary.as_bytes())
            || (self.status == SubagentStatus::Completed && !self.pending_approvals.is_empty())
        {
            return Err(SubagentRecordError);
        }

        Ok(())
    }
}
