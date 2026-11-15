use super::{
    SubagentDigest, SubagentJournal, SubagentPlanV1, SubagentRecord, SubagentRecordError,
    SubagentResources, decode_entry,
};
use crate::subagents::{
    ReservationAction, ReservationPurpose, SubagentCheckpointV1, SubagentPlanApprovalV1,
    SubagentPlanDecision, SubagentReservationV1, SubagentResultV1,
};
use crate::{AuditEventKind, SignedEntry};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Request {
    reservation: SubagentReservationV1,
    seq: u64,
    settled: Option<SubagentResources>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Prepared,
    Preview,
    CancelledPreview,
    Started,
    Closed,
}

pub(super) struct PlanLedger {
    pub plan: SubagentPlanV1,
    pub seq: u64,
    pub parent_skill: Option<crate::SkillSnapshotId>,
    pub case_scope: crate::CaseScope,
    entry_hash: SubagentDigest,
    phase: Phase,
    consent: Option<SubagentDigest>,
    operations: BTreeSet<SubagentDigest>,
    requests: BTreeMap<SubagentDigest, Request>,
    request_identities: BTreeMap<SubagentDigest, SubagentDigest>,
    allocation: Option<SubagentDigest>,
    charged: SubagentResources,
    released: SubagentResources,
    task_charged: BTreeMap<Option<SubagentDigest>, SubagentResources>,
    pub checkpoints: BTreeMap<SubagentDigest, Vec<SubagentCheckpointV1>>,
    pub results: BTreeMap<SubagentDigest, SubagentResultV1>,
}
impl PlanLedger {
    pub(super) fn new(
        plan: SubagentPlanV1,
        entry_hash: SubagentDigest,
        seq: u64,
        parent_skill: Option<crate::SkillSnapshotId>,
        case_scope: crate::CaseScope,
    ) -> Self {
        Self {
            plan,
            seq,
            parent_skill,
            case_scope,
            entry_hash,
            phase: Phase::Prepared,
            consent: None,
            operations: BTreeSet::new(),
            requests: BTreeMap::new(),
            request_identities: BTreeMap::new(),
            allocation: None,
            charged: SubagentResources::default(),
            released: SubagentResources::default(),
            task_charged: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            results: BTreeMap::new(),
        }
    }
    pub(super) fn outstanding(&self) -> Result<SubagentResources, SubagentRecordError> {
        if self.phase == Phase::Prepared {
            return Ok(SubagentResources::default());
        }
        let mut outstanding = self
            .plan
            .reservation
            .checked_sub(self.charged)?
            .checked_sub(self.released)?;
        outstanding.rounds = self
            .plan
            .reservation
            .rounds
            .checked_sub(self.total_usage()?.rounds)
            .and_then(|n| n.checked_sub(self.released.rounds))
            .ok_or(SubagentRecordError)?;
        Ok(outstanding)
    }
    pub(super) fn turn_usage(&self) -> Result<SubagentResources, SubagentRecordError> {
        self.task_charged
            .iter()
            // Parent requests already count in the journal's root round counter.
            .filter_map(|(task, amount)| task.is_some().then_some(amount))
            .try_fold(SubagentResources::default(), |total, used| {
                total.checked_add(*used)
            })
    }
    pub(super) fn total_usage(&self) -> Result<SubagentResources, SubagentRecordError> {
        self.task_charged
            .values()
            .try_fold(SubagentResources::default(), |total, used| {
                total.checked_add(*used)
            })
    }
    pub(super) fn is_open(&self) -> bool {
        self.phase != Phase::Closed
    }
    pub(super) fn is_preview(&self) -> bool {
        matches!(
            self.phase,
            Phase::Prepared | Phase::Preview | Phase::CancelledPreview
        )
    }
    pub(super) fn needs_preview_hold(&self) -> bool {
        self.phase == Phase::Prepared
    }
    pub(super) fn recovery_allocation(
        &self,
    ) -> Result<Option<SubagentReservationV1>, SubagentRecordError> {
        if self.phase != Phase::Started {
            return Ok(None);
        }
        let allocation = crate::subagents::broker::plan_transition(
            &self.plan,
            ReservationAction::StartPlan,
            Some(self.operation(ReservationAction::HoldPreview)),
            self.consent.unwrap_or(self.entry_hash),
        )
        .map_err(|_| SubagentRecordError)?;
        if Some(allocation.identity()?) != self.allocation {
            return Err(SubagentRecordError);
        }
        Ok(Some(allocation))
    }
    fn approval(
        &mut self,
        value: &SubagentPlanApprovalV1,
        entry: &SignedEntry,
    ) -> Result<(), SubagentRecordError> {
        if self.phase != Phase::Preview
            || self.consent.is_some()
            || !value.matches(&self.plan)?
            || entry.at > self.plan.deadline_at
        {
            return Err(SubagentRecordError);
        }
        match value.decision {
            SubagentPlanDecision::Approve => {
                self.consent = Some(SubagentDigest::from_bytes(entry.hash));
            }
            SubagentPlanDecision::Cancel => self.phase = Phase::CancelledPreview,
        }
        Ok(())
    }
    fn reservation(
        &mut self,
        value: &SubagentReservationV1,
        seq: u64,
    ) -> Result<(), SubagentRecordError> {
        value.validate_against(&self.plan)?;
        if self.operations.contains(&value.operation_id)
            || self.phase == Phase::Closed
            || self.operations.len() >= 32_768
        {
            return Err(SubagentRecordError);
        }
        match value.action {
            ReservationAction::HoldPreview => {
                if self.phase != Phase::Prepared
                    || value.amount != self.plan.reservation
                    || value.cause_sha256 != self.entry_hash
                {
                    return Err(SubagentRecordError);
                }
                self.phase = Phase::Preview;
            }
            ReservationAction::StartPlan => self.start(value)?,
            ReservationAction::ReserveRequest => self.reserve(value, seq)?,
            ReservationAction::SettleRequest => self.settle(value)?,
            ReservationAction::ReleasePlan | ReservationAction::ExpirePreview => {
                self.release(value)?;
            }
        }
        self.operations.insert(value.operation_id);
        Ok(())
    }
    fn operation(&self, action: ReservationAction) -> SubagentDigest {
        SubagentReservationV1::operation_id(
            self.plan.plan_id,
            None,
            action,
            ReservationPurpose::Plan,
            0,
        )
    }
    fn start(&mut self, value: &SubagentReservationV1) -> Result<(), SubagentRecordError> {
        if self.phase != Phase::Preview
            || value.amount != self.plan.reservation
            || value.parent_operation != Some(self.operation(ReservationAction::HoldPreview))
            || value.cause_sha256 != self.consent.unwrap_or(self.entry_hash)
            || (self.plan.requires_signed_consent()? && self.consent.is_none())
        {
            return Err(SubagentRecordError);
        }
        self.phase = Phase::Started;
        self.allocation = Some(value.identity()?);
        Ok(())
    }
    fn reserve(
        &mut self,
        value: &SubagentReservationV1,
        seq: u64,
    ) -> Result<(), SubagentRecordError> {
        let task = value.task_id;
        let limit = match task {
            Some(task) => {
                self.plan
                    .tasks
                    .iter()
                    .find(|t| t.task_id == task)
                    .ok_or(SubagentRecordError)?
                    .budget
            }
            None => self.plan.coordination,
        };
        if self.phase != Phase::Started
            || task.is_some_and(|task| self.results.contains_key(&task))
            || value.parent_operation != Some(self.operation(ReservationAction::StartPlan))
            || !self.valid_cause(
                task,
                value.cause_sha256,
                value.purpose == ReservationPurpose::Model,
            )?
        {
            return Err(SubagentRecordError);
        }
        let mut used = self.task_charged.get(&task).copied().unwrap_or_default();
        for request in self
            .requests
            .values()
            .filter(|r| r.reservation.task_id == task && r.settled.is_none())
        {
            used = used.checked_add(request.reservation.amount)?;
        }
        if !used.checked_add(value.amount)?.within(limit) {
            return Err(SubagentRecordError);
        }
        self.requests.insert(
            value.operation_id,
            Request {
                reservation: value.clone(),
                seq,
                settled: None,
            },
        );
        self.request_identities
            .insert(value.identity()?, value.operation_id);
        Ok(())
    }
    pub(super) fn recovery_requests(
        &self,
        task: SubagentDigest,
    ) -> Vec<(SubagentReservationV1, Option<SubagentResources>)> {
        self.requests
            .values()
            .filter(|request| request.reservation.task_id == Some(task))
            .map(|request| (request.reservation.clone(), request.settled))
            .collect()
    }
    pub(super) fn allocation(&self) -> Option<SubagentDigest> {
        self.allocation
    }
    pub(super) fn entry_hash(&self) -> SubagentDigest {
        self.entry_hash
    }
    pub(super) fn request_by_identity(
        &self,
        identity: SubagentDigest,
    ) -> Result<(&SubagentReservationV1, u64), SubagentRecordError> {
        self.request(
            *self
                .request_identities
                .get(&identity)
                .ok_or(SubagentRecordError)?,
        )
    }
    pub(super) fn request(
        &self,
        id: SubagentDigest,
    ) -> Result<(&SubagentReservationV1, u64), SubagentRecordError> {
        let request = self.requests.get(&id).ok_or(SubagentRecordError)?;
        Ok((&request.reservation, request.seq))
    }
    pub(super) fn matches_dispatch_reservation(
        &self,
        request: &SubagentReservationV1,
        attribution: &super::TaskDispatchAttribution,
    ) -> Result<bool, SubagentRecordError> {
        if attribution.reservation_sha256 == request.identity()? {
            return Ok(request.purpose == ReservationPurpose::Tool);
        }
        if request.purpose != ReservationPurpose::Cloud {
            return Ok(false);
        }
        for ticket in self.requests.values() {
            let tool = &ticket.reservation;
            if tool.purpose == ReservationPurpose::Tool
                && tool.task_id == request.task_id
                && tool.request_ordinal == request.request_ordinal
                && tool.cause_sha256 == request.cause_sha256
                && tool.identity()? == attribution.reservation_sha256
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn valid_cause(
        &self,
        task: Option<SubagentDigest>,
        hash: SubagentDigest,
        initial: bool,
    ) -> Result<bool, SubagentRecordError> {
        if initial && hash == self.entry_hash {
            return Ok(true);
        }
        self.checkpoints
            .iter()
            .filter(|(id, _)| task.is_none_or(|task| **id == task))
            .flat_map(|(_, checkpoints)| checkpoints)
            .try_fold(false, |found, cp| Ok(found || cp.identity()? == hash))
    }
    fn settle(&mut self, value: &SubagentReservationV1) -> Result<(), SubagentRecordError> {
        let task = value.task_id;
        if !self.valid_cause(task, value.cause_sha256, false)? {
            return Err(SubagentRecordError);
        }
        let request = self
            .requests
            .get_mut(&value.parent_operation.ok_or(SubagentRecordError)?)
            .ok_or(SubagentRecordError)?;
        if request.settled.is_some()
            || request.reservation.task_id != task
            || request.reservation.request_ordinal != value.request_ordinal
            || request.reservation.purpose != value.purpose
            || !value.amount.within(request.reservation.amount)
        {
            return Err(SubagentRecordError);
        }
        // Unknown usage is kept charged to the task and held at the case level.
        let amount = if value.accounting_audit_sha256.is_some() {
            value.amount
        } else {
            request.reservation.amount
        };
        let charged = self.task_charged.entry(task).or_default();
        *charged = charged.checked_add(amount)?;
        if value.accounting_audit_sha256.is_some() {
            self.charged = self.charged.checked_add(amount)?;
        }
        request.settled = Some(amount);
        Ok(())
    }
    fn release(&mut self, value: &SubagentReservationV1) -> Result<(), SubagentRecordError> {
        let expire = value.action == ReservationAction::ExpirePreview;
        let parent = self.operation(if expire {
            ReservationAction::HoldPreview
        } else {
            ReservationAction::StartPlan
        });
        if (expire && !matches!(self.phase, Phase::Preview | Phase::CancelledPreview))
            || (!expire && self.phase != Phase::Started)
            || value.parent_operation != Some(parent)
            || (!expire
                && (self.results.len() != self.plan.tasks.len()
                    || self.requests.values().any(|r| r.settled.is_none())))
        {
            return Err(SubagentRecordError);
        }
        let used = self.total_usage()?;
        let unused = self.plan.reservation.checked_sub(used)?;
        if value.amount != unused {
            return Err(SubagentRecordError);
        }
        if expire {
            if value.cause_sha256 != self.entry_hash {
                return Err(SubagentRecordError);
            }
        } else if !self
            .checkpoints
            .values()
            .flatten()
            .filter(|cp| cp.terminal)
            .map(SubagentRecord::identity)
            .collect::<Result<Vec<_>, _>>()?
            .contains(&value.cause_sha256)
        {
            return Err(SubagentRecordError);
        }
        self.released = unused;
        self.phase = Phase::Closed;
        Ok(())
    }
}

impl SubagentJournal {
    pub(super) fn plan_transition(
        &mut self,
        entry: &SignedEntry,
    ) -> Result<(), SubagentRecordError> {
        match entry.kind {
            AuditEventKind::SubagentPlanApprovalV1 => {
                let value: SubagentPlanApprovalV1 = decode_entry(entry)?;
                self.plans
                    .get_mut(&value.plan_sha256)
                    .ok_or(SubagentRecordError)?
                    .approval(&value, entry)
            }
            AuditEventKind::SubagentReservationV1 => {
                let value: SubagentReservationV1 = decode_entry(entry)?;
                if value.action == ReservationAction::StartPlan {
                    self.validate_admission(&value, entry.at)?;
                }
                if value.action == ReservationAction::ReserveRequest {
                    let plan = &self
                        .plans
                        .get(&value.plan_sha256)
                        .ok_or(SubagentRecordError)?
                        .plan;
                    let deadline = value
                        .task_id
                        .map_or(Some(plan.deadline_at), |task| {
                            plan.tasks
                                .iter()
                                .find(|spec| spec.task_id == task)
                                .map(|spec| spec.deadline_at)
                        })
                        .ok_or(SubagentRecordError)?;
                    if entry.at > deadline {
                        return Err(SubagentRecordError);
                    }
                }
                self.validate_accounting(&value)?;
                self.plans
                    .get_mut(&value.plan_sha256)
                    .ok_or(SubagentRecordError)?
                    .reservation(&value, entry.seq)
            }
            AuditEventKind::SubagentCheckpointV1 => {
                let value: SubagentCheckpointV1 = decode_entry(entry)?;
                self.validate_checkpoint_admissions(&value, entry)?;
                self.checkpoint_audit_hashes
                    .insert(value.identity()?, SubagentDigest::from_bytes(entry.hash));
                self.checkpoint_sequences
                    .insert(value.identity()?, entry.seq);
                self.checkpoint(value)
            }
            AuditEventKind::SubagentResultV1 => self.result(decode_entry(entry)?),
            _ => Err(SubagentRecordError),
        }
    }
    fn validate_admission(
        &self,
        value: &SubagentReservationV1,
        at: u64,
    ) -> Result<(), SubagentRecordError> {
        let state = self
            .plans
            .get(&value.plan_sha256)
            .ok_or(SubagentRecordError)?;
        let plan = &state.plan;
        let rules = plan.policy.rules()?;
        let budget = self
            .budget
            .status(&rules)
            .map_err(|_| SubagentRecordError)?;
        if at > plan.deadline_at
            || plan.budget_checkpoint_sha256.as_bytes() != &self.budget.checkpoint()
            || plan.usage.tokens != budget.usage.model_tokens
            || plan.usage.calls != budget.usage.tool_calls
            || plan.usage.cloud_bytes != budget.usage.cloud_bytes
            || plan.usage.rounds != self.rounds_used(&plan.turn_id)?
            || plan.prior_reserved
                != self
                    .outstanding_for_turn(Some(&plan.turn_id))?
                    .checked_sub(state.outstanding()?)?
        {
            return Err(SubagentRecordError);
        }
        for task in &plan.tasks {
            if let Some(scope) = &task.remote_scope {
                let scope = crate::CaseScope::parse(scope).map_err(|_| SubagentRecordError)?;
                if !scope.is_within(&self.scope) {
                    return Err(SubagentRecordError);
                }
            }
        }
        Ok(())
    }
    fn checkpoint(&mut self, value: SubagentCheckpointV1) -> Result<(), SubagentRecordError> {
        let plan = self
            .plans
            .values_mut()
            .find(|p| p.plan.tasks.iter().any(|t| t.task_id == value.task_id))
            .ok_or(SubagentRecordError)?;
        if plan.phase != Phase::Started
            || value.case_id != self.case.as_str()
            || value
                .admitted_sources
                .iter()
                .any(|hash| !self.sources.contains(hash))
            || plan.results.contains_key(&value.task_id)
        {
            return Err(SubagentRecordError);
        }
        let checkpoints = plan.checkpoints.entry(value.task_id).or_default();
        let previous = checkpoints.last();
        if previous.is_some_and(|cp| cp.terminal)
            || value.previous_checkpoint != previous.map(SubagentRecord::identity).transpose()?
            || value.first != previous.map_or(1, |cp| cp.last + 1)
            || checkpoints.iter().map(|cp| cp.chunk_bytes).sum::<u64>() + value.chunk_bytes
                > 16 * 1024 * 1024
        {
            return Err(SubagentRecordError);
        }
        checkpoints.push(value);
        Ok(())
    }
    fn result(&mut self, value: SubagentResultV1) -> Result<(), SubagentRecordError> {
        let plan = self
            .plans
            .values_mut()
            .find(|p| p.plan.tasks.iter().any(|t| t.task_id == value.task_id))
            .ok_or(SubagentRecordError)?;
        let last = plan
            .checkpoints
            .get(&value.task_id)
            .and_then(|c| c.last())
            .ok_or(SubagentRecordError)?;
        if value.case_id != self.case.as_str()
            || !last.terminal
            || value.checkpoint_sha256 != last.identity()?
            || !value.usage.within(
                plan.plan
                    .tasks
                    .iter()
                    .find(|t| t.task_id == value.task_id)
                    .ok_or(SubagentRecordError)?
                    .budget,
            )
            || plan.results.insert(value.task_id, value).is_some()
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
