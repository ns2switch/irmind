use super::{
    SubagentDigest, SubagentPlanV1, SubagentRecord, SubagentRecordError, SubagentResources,
};
use crate::AuditEventKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationAction {
    HoldPreview,
    StartPlan,
    ReserveRequest,
    SettleRequest,
    ReleasePlan,
    ExpirePreview,
}
impl ReservationAction {
    const fn code(self) -> u16 {
        match self {
            Self::HoldPreview => 1,
            Self::StartPlan => 2,
            Self::ReserveRequest => 3,
            Self::SettleRequest => 4,
            Self::ReleasePlan => 5,
            Self::ExpirePreview => 6,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReservationPurpose {
    Plan,
    Model,
    Tool,
    Cloud,
}
impl ReservationPurpose {
    const fn code(self) -> u16 {
        match self {
            Self::Plan => 1,
            Self::Model => 2,
            Self::Tool => 3,
            Self::Cloud => 4,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentReservationV1 {
    format_version: u8,
    pub operation_id: SubagentDigest,
    pub plan_sha256: SubagentDigest,
    pub task_id: Option<SubagentDigest>,
    pub request_ordinal: u64,
    pub action: ReservationAction,
    pub purpose: ReservationPurpose,
    pub amount: SubagentResources,
    pub parent_operation: Option<SubagentDigest>,
    pub cause_sha256: SubagentDigest,
    pub accounting_audit_sha256: Option<SubagentDigest>,
}
impl SubagentReservationV1 {
    pub fn operation_id(
        plan_id: SubagentDigest,
        task: Option<SubagentDigest>,
        action: ReservationAction,
        purpose: ReservationPurpose,
        ordinal: u64,
    ) -> SubagentDigest {
        let mut bytes = b"irmind-subagent-operation-id-v1\0".to_vec();
        bytes.extend_from_slice(plan_id.as_bytes());
        bytes.push(u8::from(task.is_some()));
        if let Some(task) = task {
            bytes.extend_from_slice(task.as_bytes());
        }
        bytes.extend_from_slice(&action.code().to_be_bytes());
        bytes.extend_from_slice(&purpose.code().to_be_bytes());
        bytes.extend_from_slice(&ordinal.to_be_bytes());
        SubagentDigest::from_bytes(crate::sha256(&bytes))
    }
    pub fn validate_against(&self, plan: &SubagentPlanV1) -> Result<(), SubagentRecordError> {
        self.validate()?;
        if self.plan_sha256 != plan.identity()?
            || self.operation_id
                != Self::operation_id(
                    plan.plan_id,
                    self.task_id,
                    self.action,
                    self.purpose,
                    self.request_ordinal,
                )
        {
            return Err(SubagentRecordError);
        }
        let limit = if let Some(task) = self.task_id {
            plan.tasks
                .iter()
                .find(|t| t.task_id == task)
                .ok_or(SubagentRecordError)?
                .budget
        } else {
            plan.reservation
        };
        if !self.amount.within(limit) {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
impl SubagentRecord for SubagentReservationV1 {
    const KIND: AuditEventKind = AuditEventKind::SubagentReservationV1;
    const DOMAIN: &'static [u8] = b"irmind-subagent-reservation-v1\0";
    fn validate(&self) -> Result<(), SubagentRecordError> {
        self.amount.validate()?;
        let plan_transition = matches!(
            self.action,
            ReservationAction::HoldPreview
                | ReservationAction::StartPlan
                | ReservationAction::ReleasePlan
                | ReservationAction::ExpirePreview
        );
        if self.format_version != 1
            || plan_transition != (self.purpose == ReservationPurpose::Plan)
            || plan_transition != self.task_id.is_none()
            || plan_transition != (self.request_ordinal == 0)
            || (self.action == ReservationAction::HoldPreview) != self.parent_operation.is_none()
            || (self.action != ReservationAction::SettleRequest
                && self.accounting_audit_sha256.is_some())
        {
            return Err(SubagentRecordError);
        }
        match self.purpose {
            ReservationPurpose::Model if self.amount.calls != 0 || self.amount.cloud_bytes != 0 => {
                Err(SubagentRecordError)
            }
            ReservationPurpose::Tool
                if self.amount.tokens != 0
                    || self.amount.rounds != 0
                    || self.amount.calls > 1
                    || self.amount.cloud_bytes != 0 =>
            {
                Err(SubagentRecordError)
            }
            ReservationPurpose::Cloud
                if self.amount.tokens != 0 || self.amount.calls != 0 || self.amount.rounds != 0 =>
            {
                Err(SubagentRecordError)
            }
            _ => Ok(()),
        }
    }
}
