use super::{SubagentDigest, SubagentJournal, SubagentRecordError, SubagentResources};
use crate::subagents::{ReservationAction, ReservationPurpose, SubagentReservationV1};
use crate::{AuditEventKind, SignedEntry, Tool, UsageEvent};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDispatchAttribution {
    pub version: u8,
    pub tool: String,
    pub reserved_bytes: u64,
    pub task_id: SubagentDigest,
    pub call_id: String,
    pub proposal_sha256: SubagentDigest,
    pub reservation_sha256: SubagentDigest,
    pub arguments_sha256: SubagentDigest,
    pub source_set_sha256: SubagentDigest,
}
impl TaskDispatchAttribution {
    pub fn canonical(&self) -> Result<Vec<u8>, SubagentRecordError> {
        let tool = Tool::parse(&self.tool).map_err(|_| SubagentRecordError)?;
        if self.version != 1
            || tool.as_str() != self.tool
            || self.call_id.is_empty()
            || self.call_id.len() > 128
            || !self
                .call_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            || (tool != Tool::ObjectRead && self.reserved_bytes != 0)
            || self.reserved_bytes > 1_073_741_824
        {
            return Err(SubagentRecordError);
        }
        super::super::codec::bounded_json(self, 256 * 1024)
    }
}

pub(super) struct Accounted {
    pub seq: u64,
    pub at: u64,
    pub actor: crate::Actor,
    pub amount: SubagentResources,
    pub attribution: Option<TaskDispatchAttribution>,
}
impl SubagentJournal {
    pub(super) fn observe_accounting(
        &mut self,
        entry: &SignedEntry,
    ) -> Result<(), SubagentRecordError> {
        if !self.plans.values().any(super::PlanLedger::is_open) {
            // Only requests inside an open plan can cite these receipts. Root
            // accounting outside plans is already streamed by BudgetReplay.
            return Ok(());
        }
        if self.agent.as_ref() != Some(&entry.actor)
            && !(entry.actor == crate::Actor::Analyst && entry.kind == AuditEventKind::ModelUsage)
        {
            return Ok(());
        }
        let (amount, attribution) = match entry.kind {
            AuditEventKind::ModelUsage => {
                let usage: UsageEvent =
                    serde_json::from_str(&entry.payload).map_err(|_| SubagentRecordError)?;
                (
                    SubagentResources {
                        tokens: usage
                            .input_tokens
                            .checked_add(usage.output_tokens)
                            .ok_or(SubagentRecordError)?,
                        rounds: 1,
                        ..SubagentResources::default()
                    },
                    None,
                )
            }
            AuditEventKind::Allowed | AuditEventKind::ToolDispatch => {
                let value: TaskDispatchAttribution =
                    serde_json::from_str(&entry.payload).map_err(|_| SubagentRecordError)?;
                if value.canonical()? != entry.payload.as_bytes() {
                    return Err(SubagentRecordError);
                }
                let amount = SubagentResources {
                    calls: 1,
                    cloud_bytes: value.reserved_bytes,
                    ..SubagentResources::default()
                };
                (amount, Some(value))
            }
            _ => return Ok(()),
        };
        amount.validate()?;
        // At most 256 tasks × 100 shared rounds, plus 10,000 case calls;
        // reserve headroom without retaining arbitrary unrelated zero reports.
        if self.accounting.len() >= 65_536 {
            return Err(SubagentRecordError);
        }
        self.accounting.insert(
            SubagentDigest::from_bytes(entry.hash),
            Accounted {
                seq: entry.seq,
                at: entry.at,
                actor: entry.actor.clone(),
                amount,
                attribution,
            },
        );
        Ok(())
    }

    pub(super) fn validate_accounting(
        &mut self,
        value: &SubagentReservationV1,
    ) -> Result<(), SubagentRecordError> {
        if value.action != ReservationAction::SettleRequest {
            return Ok(());
        }
        let Some(hash) = value.accounting_audit_sha256 else {
            return Ok(());
        };
        let accounted = self.accounting.get(&hash).ok_or(SubagentRecordError)?;
        let state = self
            .plans
            .get(&value.plan_sha256)
            .ok_or(SubagentRecordError)?;
        let request = state.request(value.parent_operation.ok_or(SubagentRecordError)?)?;
        let checkpoint_seq = self
            .checkpoint_sequences
            .get(&value.cause_sha256)
            .ok_or(SubagentRecordError)?;
        let mut expected = accounted.amount;
        if value.purpose == ReservationPurpose::Tool {
            expected.cloud_bytes = 0;
        }
        if value.purpose == ReservationPurpose::Cloud {
            expected.calls = 0;
        }
        if expected != value.amount
            || self.accounted.contains(&(hash, value.purpose))
            || accounted.seq <= request.1
            || (value.task_id.is_some() && accounted.seq >= *checkpoint_seq)
            || (value.task_id.is_none() && accounted.seq > self.seq)
            || accounted.actor
                != if value.task_id.is_none() {
                    crate::Actor::Analyst
                } else {
                    self.agent.clone().ok_or(SubagentRecordError)?
                }
        {
            return Err(SubagentRecordError);
        }
        match (&accounted.attribution, value.purpose) {
            (None, ReservationPurpose::Model) => {}
            (Some(attr), ReservationPurpose::Tool | ReservationPurpose::Cloud) => {
                let task = state
                    .plan
                    .tasks
                    .iter()
                    .find(|t| Some(t.task_id) == value.task_id)
                    .ok_or(SubagentRecordError)?;
                if Some(attr.task_id) != value.task_id
                    || !state.matches_dispatch_reservation(request.0, attr)?
                    || attr.source_set_sha256 != task.source_set_sha256
                {
                    return Err(SubagentRecordError);
                }
            }
            _ => return Err(SubagentRecordError),
        }
        self.accounted.insert((hash, value.purpose));
        Ok(())
    }
}
