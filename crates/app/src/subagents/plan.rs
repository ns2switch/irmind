use super::{SubagentDigest, SubagentRecord, SubagentRecordError, SubagentResources, codec};
use crate::{AuditEventKind, CaseScope};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentPolicySnapshot {
    version: u8,
    denied_tools: Vec<String>,
    scope: Option<String>,
    max_tool_calls_per_case: u64,
    max_model_rounds_per_turn: u64,
    max_model_result_bytes: u64,
    max_model_tokens_per_case: u64,
    max_object_read_bytes: u64,
    max_object_bytes_per_case: u64,
    object_transfer_approval_bytes: u64,
}
impl SubagentPolicySnapshot {
    pub fn new(policy: &irmind_domain::PolicyRules) -> Result<Self, SubagentRecordError> {
        policy.validate().map_err(|_| SubagentRecordError)?;
        let mut denied_tools = policy
            .denied_tools
            .iter()
            .map(|t| t.as_str().into())
            .collect::<Vec<_>>();
        denied_tools.sort();
        denied_tools.dedup();
        Ok(Self {
            version: 1,
            denied_tools,
            scope: policy
                .scope
                .as_ref()
                .map(CaseScope::to_current_string)
                .transpose()
                .map_err(|_| SubagentRecordError)?,
            max_tool_calls_per_case: policy.max_tool_calls_per_case as u64,
            max_model_rounds_per_turn: policy.max_model_rounds_per_turn as u64,
            max_model_result_bytes: policy.max_model_result_bytes as u64,
            max_model_tokens_per_case: policy.max_model_tokens_per_case,
            max_object_read_bytes: policy.max_object_read_bytes,
            max_object_bytes_per_case: policy.max_object_bytes_per_case,
            object_transfer_approval_bytes: policy.object_transfer_approval_bytes,
        })
    }
    pub fn rules(&self) -> Result<irmind_domain::PolicyRules, SubagentRecordError> {
        if self.version != 1 {
            return Err(SubagentRecordError);
        }
        codec::sorted(&self.denied_tools, 32)?;
        let denied_tools = self
            .denied_tools
            .iter()
            .map(|id| {
                let tool = irmind_domain::Tool::parse(id).map_err(|_| SubagentRecordError)?;
                if tool.as_str() != id {
                    return Err(SubagentRecordError);
                }
                Ok(tool)
            })
            .collect::<Result<_, _>>()?;
        let policy = irmind_domain::PolicyRules {
            denied_tools,
            scope: self
                .scope
                .as_deref()
                .map(CaseScope::parse)
                .transpose()
                .map_err(|_| SubagentRecordError)?,
            max_tool_calls_per_case: usize::try_from(self.max_tool_calls_per_case)
                .map_err(|_| SubagentRecordError)?,
            max_model_rounds_per_turn: usize::try_from(self.max_model_rounds_per_turn)
                .map_err(|_| SubagentRecordError)?,
            max_model_result_bytes: usize::try_from(self.max_model_result_bytes)
                .map_err(|_| SubagentRecordError)?,
            max_model_tokens_per_case: self.max_model_tokens_per_case,
            max_object_read_bytes: self.max_object_read_bytes,
            max_object_bytes_per_case: self.max_object_bytes_per_case,
            object_transfer_approval_bytes: self.object_transfer_approval_bytes,
        };
        policy.validate().map_err(|_| SubagentRecordError)?;
        Ok(policy)
    }
    pub fn limits(&self) -> Result<SubagentResources, SubagentRecordError> {
        self.rules()?;
        Ok(SubagentResources {
            tokens: self.max_model_tokens_per_case,
            calls: self.max_tool_calls_per_case,
            rounds: self.max_model_rounds_per_turn,
            cloud_bytes: self.max_object_bytes_per_case,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentTaskSpec {
    pub task_id: SubagentDigest,
    pub ordinal: u64,
    pub type_snapshot_sha256: SubagentDigest,
    pub nonce: String,
    pub source_set_sha256: SubagentDigest,
    pub remote_scope: Option<String>,
    pub objective: String,
    pub skill_snapshot_sha256: Option<SubagentDigest>,
    pub budget: SubagentResources,
    pub deadline_at: u64,
}
impl SubagentTaskSpec {
    fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::uuid(&self.nonce)?;
        self.budget.validate()?;
        if self.objective.trim().is_empty()
            || self.objective.len() > 2048
            || self.budget.tokens == 0
            || self.budget.rounds == 0
        {
            return Err(SubagentRecordError);
        }
        if let Some(scope) = &self.remote_scope
            && (scope.len() > 1000
                || !matches!(CaseScope::parse(scope), Ok(CaseScope::Remote { .. })))
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}

/// Proposed data, never a reservation ticket or permission to execute.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentPlanV1 {
    format_version: u8,
    pub plan_id: SubagentDigest,
    pub case_id: String,
    pub turn_id: String,
    pub ordinal: u64,
    pub parent_checkpoint_sha256: SubagentDigest,
    pub budget_checkpoint_sha256: SubagentDigest,
    pub policy: SubagentPolicySnapshot,
    pub case_limits: SubagentResources,
    pub usage: SubagentResources,
    pub prior_reserved: SubagentResources,
    pub remaining: SubagentResources,
    pub reservation: SubagentResources,
    pub coordination: SubagentResources,
    pub deadline_at: u64,
    pub tasks: Vec<SubagentTaskSpec>,
}
impl SubagentPlanV1 {
    pub fn plan_id(
        case: &str,
        turn: &str,
        ordinal: u64,
    ) -> Result<SubagentDigest, SubagentRecordError> {
        codec::uuid(case)?;
        codec::uuid(turn)?;
        if ordinal == 0 {
            return Err(SubagentRecordError);
        }
        let mut bytes = b"irmind-subagent-plan-id-v1\0".to_vec();
        bytes.extend_from_slice(
            uuid::Uuid::parse_str(case)
                .map_err(|_| SubagentRecordError)?
                .as_bytes(),
        );
        bytes.extend_from_slice(
            uuid::Uuid::parse_str(turn)
                .map_err(|_| SubagentRecordError)?
                .as_bytes(),
        );
        bytes.extend_from_slice(&ordinal.to_be_bytes());
        Ok(SubagentDigest::from_bytes(crate::sha256(&bytes)))
    }
    pub fn task_id(plan: SubagentDigest, ordinal: u64) -> SubagentDigest {
        let mut bytes = b"irmind-subagent-task-id-v1\0".to_vec();
        bytes.extend_from_slice(plan.as_bytes());
        bytes.extend_from_slice(&ordinal.to_be_bytes());
        SubagentDigest::from_bytes(crate::sha256(&bytes))
    }
    pub fn requires_signed_consent(&self) -> Result<bool, SubagentRecordError> {
        self.validate()?;
        self.reservation.requires_signed_consent(self.remaining)
    }
}
impl SubagentRecord for SubagentPlanV1 {
    const KIND: AuditEventKind = AuditEventKind::SubagentPlanV1;
    const DOMAIN: &'static [u8] = b"irmind-subagent-plan-v1\0";
    fn validate(&self) -> Result<(), SubagentRecordError> {
        let limits = self.policy.limits()?;
        for value in [
            self.case_limits,
            self.usage,
            self.prior_reserved,
            self.remaining,
            self.reservation,
            self.coordination,
        ] {
            value.validate()?;
        }
        if self.format_version != 1
            || self.tasks.is_empty()
            || self.tasks.len() > 16
            || self.plan_id != Self::plan_id(&self.case_id, &self.turn_id, self.ordinal)?
            || !self.case_limits.within(limits)
            || self
                .case_limits
                .checked_sub(self.usage)?
                .checked_sub(self.prior_reserved)?
                != self.remaining
            || !self.reservation.within(self.remaining)
        {
            return Err(SubagentRecordError);
        }
        let mut total = self.coordination;
        let mut nonces = std::collections::BTreeSet::new();
        for (ordinal, task) in self.tasks.iter().enumerate() {
            task.validate()?;
            if task.ordinal != ordinal as u64
                || task.task_id != Self::task_id(self.plan_id, task.ordinal)
                || task.deadline_at > self.deadline_at
                || !nonces.insert(&task.nonce)
            {
                return Err(SubagentRecordError);
            }
            total = total.checked_add(task.budget)?;
        }
        if total != self.reservation {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubagentPlanDecision {
    Approve,
    Cancel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentPlanApprovalV1 {
    format_version: u8,
    pub plan_sha256: SubagentDigest,
    pub budget_checkpoint_sha256: SubagentDigest,
    pub remaining_tokens: u64,
    pub remaining_calls: u64,
    pub reserved_tokens: u64,
    pub reserved_calls: u64,
    pub decision: SubagentPlanDecision,
}
impl SubagentPlanApprovalV1 {
    pub fn new(
        plan: &SubagentPlanV1,
        decision: SubagentPlanDecision,
    ) -> Result<Self, SubagentRecordError> {
        let value = Self {
            format_version: 1,
            plan_sha256: plan.identity()?,
            budget_checkpoint_sha256: plan.budget_checkpoint_sha256,
            remaining_tokens: plan.remaining.tokens,
            remaining_calls: plan.remaining.calls,
            reserved_tokens: plan.reservation.tokens,
            reserved_calls: plan.reservation.calls,
            decision,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn matches(&self, plan: &SubagentPlanV1) -> Result<bool, SubagentRecordError> {
        self.validate()?;
        Ok(self.plan_sha256 == plan.identity()?
            && self.budget_checkpoint_sha256 == plan.budget_checkpoint_sha256
            && self.remaining_tokens == plan.remaining.tokens
            && self.remaining_calls == plan.remaining.calls
            && self.reserved_tokens == plan.reservation.tokens
            && self.reserved_calls == plan.reservation.calls)
    }
}
impl SubagentRecord for SubagentPlanApprovalV1 {
    const KIND: AuditEventKind = AuditEventKind::SubagentPlanApprovalV1;
    const DOMAIN: &'static [u8] = b"irmind-subagent-plan-approval-v1\0";
    fn validate(&self) -> Result<(), SubagentRecordError> {
        if self.format_version != 1
            || self.reserved_tokens > self.remaining_tokens
            || self.reserved_calls > self.remaining_calls
            || self.remaining_tokens > 10_000_000
            || self.remaining_calls > 10_000
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
