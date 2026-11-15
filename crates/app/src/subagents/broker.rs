//! Case-lock transactions for bounded plans. Proposed data is never a lease.
use super::{
    AnalystPlanChoice, ReservationAction, ReservationPurpose, ReservationTransition,
    SafePlanPreview, SubagentDigest, SubagentJournal, SubagentPlanApprovalV1, SubagentPlanDecision,
    SubagentPlanV1, SubagentRecord, SubagentReservationV1, SubagentResources, SubagentSourcePageV1,
    SubagentSourceSetV1, SubagentTaskSpec, SubagentTypeSnapshotV1,
};
use crate::{AppError, AuditOrigin, CancellationToken, CaseId, Engine, SignedEntry};
use irmind_domain::{CaseScope, EvidenceHash, SkillName};

/// Untrusted proposal. The broker supplies all identities and checkpoints.
pub struct SubagentTaskProposal {
    pub type_id: String,
    pub objective: String,
    pub sources: Vec<EvidenceHash>,
    pub remote_scope: Option<CaseScope>,
    pub skill: Option<SkillName>,
    pub budget: SubagentResources,
}

/// A durable preview hold; it conveys no dispatch or approval capability.
pub struct PreparedSubagentPlan {
    preview: SafePlanPreview,
    entry_hash: SubagentDigest,
    hold: SubagentReservationV1,
}
impl PreparedSubagentPlan {
    pub const fn preview(&self) -> &SafePlanPreview {
        &self.preview
    }
}

/// Minted only after replay and trusted Analyst interaction. Every dispatch
/// still rechecks the durable allocation, policy and its request reservation.
pub struct StartedSubagentPlan {
    pub(super) plan: SubagentPlanV1,
    pub(super) entry_hash: SubagentDigest,
    pub(super) allocation: SubagentReservationV1,
}
impl StartedSubagentPlan {
    pub const fn plan(&self) -> &SubagentPlanV1 {
        &self.plan
    }
    pub const fn allocation(&self) -> &SubagentReservationV1 {
        &self.allocation
    }
    pub const fn entry_hash(&self) -> SubagentDigest {
        self.entry_hash
    }
}

fn invalid() -> AppError {
    AppError::Policy("Subagent plan is unavailable, stale or outside its validated limits".into())
}

struct AgentBatch<'a> {
    engine: Engine<'static>,
    verifier: &'a dyn crate::Verifier,
    case: &'a CaseId,
    journal: SubagentJournal,
    prior: Option<SignedEntry>,
    entries: Vec<SignedEntry>,
}
impl<'a> AgentBatch<'a> {
    fn new(
        engine: &Engine<'_>,
        case: &'a CaseId,
        verifier: &'a dyn crate::Verifier,
    ) -> Result<Self, AppError> {
        let mut local = engine.local_handle();
        local.signer = engine.skills.as_ref().ok_or_else(invalid)?.agent.clone();
        let mut journal =
            SubagentJournal::new(case.clone(), local.signer.actor()).map_err(|_| invalid())?;
        let history = engine.audit_log.entries(case)?;
        for entry in &history {
            journal.accept(entry, verifier)?;
        }
        Ok(Self {
            engine: local,
            verifier,
            case,
            journal,
            prior: history.last().cloned(),
            entries: Vec::new(),
        })
    }
    fn push<T: SubagentRecord>(&mut self, record: &T) -> Result<SubagentDigest, AppError> {
        self.push_as(record, false)
    }
    fn push_as<T: SubagentRecord>(
        &mut self,
        record: &T,
        analyst: bool,
    ) -> Result<SubagentDigest, AppError> {
        let entry = self.engine.signed_entry_after(
            self.case,
            self.entries.last().or(self.prior.as_ref()),
            if analyst {
                AuditOrigin::Analyst
            } else {
                AuditOrigin::Agent
            },
            T::KIND,
            &record.audit_payload().map_err(|_| invalid())?,
            None,
        )?;
        self.journal.accept(&entry, self.verifier)?;
        let hash = SubagentDigest::from_bytes(entry.hash);
        self.entries.push(entry);
        Ok(hash)
    }
    fn metadata<T: SubagentRecord>(&mut self, record: &T) -> Result<SubagentDigest, AppError> {
        let id = record.identity().map_err(|_| invalid())?;
        if !self.journal.has_metadata(record).map_err(|_| invalid())? {
            self.push(record)?;
        }
        Ok(id)
    }
    fn decision(
        &mut self,
        plan: &SubagentPlanV1,
        signer: std::sync::Arc<dyn crate::Signer>,
        decision: SubagentPlanDecision,
    ) -> Result<SubagentDigest, AppError> {
        let agent = self.engine.signer.clone();
        self.engine.signer = signer;
        let result = self.push_as(
            &SubagentPlanApprovalV1::new(plan, decision).map_err(|_| invalid())?,
            true,
        );
        self.engine.signer = agent;
        result
    }
    fn publish(self, cancel: &CancellationToken) -> Result<(), AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.engine.audit_log.append_batch(&self.entries)
    }
}

impl Engine<'_> {
    pub fn prepare_subagent_plan(
        &self,
        case: &CaseId,
        turn: uuid::Uuid,
        tasks: Vec<SubagentTaskProposal>,
        coordination: SubagentResources,
        cancel: &CancellationToken,
    ) -> Result<PreparedSubagentPlan, AppError> {
        self.require_attended_analyst("prepare subagent plan")?;
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        self.prepare_subagent_plan_unlocked(case, turn, tasks, coordination, cancel)
    }

    pub(crate) fn prepare_subagent_plan_unlocked(
        &self,
        case: &CaseId,
        turn: uuid::Uuid,
        tasks: Vec<SubagentTaskProposal>,
        coordination: SubagentResources,
        cancel: &CancellationToken,
    ) -> Result<PreparedSubagentPlan, AppError> {
        self.require_attended_analyst("prepare subagent plan")?;
        if self.subagents.is_none()
            || tasks.is_empty()
            || tasks.len() > 16
            || self.repo.get_case(case)?.sealed
        {
            return Err(invalid());
        }
        self.require_no_active_subagents(case)?;
        let deadline = self.clock.now()?.checked_add(600).ok_or_else(invalid)?;
        let specs = self.prepare_task_specs(case, tasks, deadline, cancel)?;
        let mut batch = AgentBatch::new(self, case, self.verifier.as_ref())?;
        let mut tasks = Vec::with_capacity(specs.len());
        for (mut task, sources, kind) in specs {
            task.type_snapshot_sha256 = batch.metadata(&kind)?;
            let mut pages = Vec::new();
            for (ordinal, hashes) in sources.chunks(256).enumerate() {
                pages.push(
                    batch.metadata(
                        &SubagentSourcePageV1::new(case, ordinal as u64, hashes.to_vec())
                            .map_err(|_| invalid())?,
                    )?,
                );
            }
            let set = SubagentSourceSetV1::new(case, sources.len() as u64, pages)
                .map_err(|_| invalid())?;
            task.source_set_sha256 = batch.metadata(&set)?;
            tasks.push(task);
        }
        let (ordinal, context) = batch
            .journal
            .preparation_context(&turn.to_string(), &self.policy)
            .map_err(|_| invalid())?;
        let plan = SubagentPlanV1::prepare(
            case,
            &turn.to_string(),
            ordinal,
            context,
            tasks,
            coordination,
            deadline,
        )
        .map_err(|_| invalid())?;
        let entry_hash = batch.push(&plan)?;
        let hold = plan_transition(&plan, ReservationAction::HoldPreview, None, entry_hash)?;
        batch.push(&hold)?;
        let confirmation_required = plan.requires_signed_consent().map_err(|_| invalid())?
            || self.confirm_all_subagent_plans()?;
        batch.publish(cancel)?;
        Ok(PreparedSubagentPlan {
            preview: SafePlanPreview {
                plan,
                confirmation_required,
            },
            entry_hash,
            hold,
        })
    }

    pub fn admit_subagent_plan(
        &self,
        prepared: &PreparedSubagentPlan,
        choice: &AnalystPlanChoice,
        cancel: &CancellationToken,
    ) -> Result<Option<StartedSubagentPlan>, AppError> {
        self.require_attended_analyst("start subagent plan")?;
        let plan = &prepared.preview.plan;
        let case = CaseId::parse(&plan.case_id).map_err(|_| invalid())?;
        let _lock = self.repo.lock_case(&case)?;
        let mut batch = AgentBatch::new(self, &case, self.verifier.as_ref())?;
        if choice.plan != plan.identity().map_err(|_| invalid())?
            || choice.budget != plan.budget_checkpoint_sha256
        {
            return Err(invalid());
        }
        if cancel.is_cancelled() || !choice.start || self.clock.now()? > plan.deadline_at {
            if !choice.start && choice.explicit {
                batch.decision(plan, self.signer.clone(), SubagentPlanDecision::Cancel)?;
            }
            let expiry = plan_transition(
                plan,
                ReservationAction::ExpirePreview,
                Some(prepared.hold.operation_id),
                prepared.entry_hash,
            )?;
            batch.push(&expiry)?;
            batch.publish(&CancellationToken::new())?;
            return Ok(None);
        }
        batch
            .journal
            .preview_is_current(plan, &self.policy)
            .map_err(|_| invalid())?;
        let required =
            prepared.preview.confirmation_required || self.confirm_all_subagent_plans()?;
        if required && !choice.explicit {
            return Err(invalid());
        }
        let mut approval_hash = prepared.entry_hash;
        if choice.explicit {
            approval_hash =
                batch.decision(plan, self.signer.clone(), SubagentPlanDecision::Approve)?;
        }

        let allocation = plan_transition(
            plan,
            ReservationAction::StartPlan,
            Some(prepared.hold.operation_id),
            approval_hash,
        )?;
        batch.push(&allocation)?;
        batch.publish(cancel)?;
        Ok(Some(StartedSubagentPlan {
            plan: prepared.preview.plan.clone(),
            entry_hash: prepared.entry_hash,
            allocation,
        }))
    }
}

type PreparedTask = (
    SubagentTaskSpec,
    Vec<SubagentDigest>,
    SubagentTypeSnapshotV1,
);
impl Engine<'_> {
    fn prepare_task_specs(
        &self,
        case: &CaseId,
        tasks: Vec<SubagentTaskProposal>,
        deadline: u64,
        cancel: &CancellationToken,
    ) -> Result<Vec<PreparedTask>, AppError> {
        let mut result = Vec::with_capacity(tasks.len());
        for task in tasks {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if task.objective.trim().is_empty()
                || task.objective.len() > 2048
                || task.sources.len() > 16_384
            {
                return Err(invalid());
            }
            let objective = self.guard.screen(&task.objective)?;
            if !objective.detections.is_empty() || objective.text.len() > 2048 {
                return Err(invalid());
            }
            let kind = SubagentTypeSnapshotV1::new(case, &task.type_id).map_err(|_| invalid())?;
            let skill_snapshot_sha256 = if let Some(skill) = task.skill {
                if !kind
                    .definition()
                    .skills()
                    .iter()
                    .any(|name| name == skill.as_str())
                {
                    return Err(invalid());
                }
                let resolved = self.resolve_skill_cancelable(&skill, cancel)?;
                Some(SubagentDigest::from_bytes(
                    *self.pin_skill_snapshot(case, &resolved, cancel)?.as_bytes(),
                ))
            } else {
                None
            };
            let mut sources = task
                .sources
                .iter()
                .map(|source| SubagentDigest::parse(source.as_str()).map_err(|_| invalid()))
                .collect::<Result<Vec<_>, _>>()?;
            sources.sort();
            if sources.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(invalid());
            }
            result.push((
                SubagentTaskSpec {
                    task_id: SubagentDigest::from_bytes([0; 32]),
                    ordinal: 0,
                    type_snapshot_sha256: SubagentDigest::from_bytes([0; 32]),
                    nonce: uuid::Uuid::new_v4().to_string(),
                    source_set_sha256: SubagentDigest::from_bytes([0; 32]),
                    remote_scope: task
                        .remote_scope
                        .as_ref()
                        .map(CaseScope::to_current_string)
                        .transpose()
                        .map_err(|_| invalid())?,
                    objective: objective.text,
                    skill_snapshot_sha256,
                    budget: task.budget,
                    deadline_at: deadline,
                },
                sources,
                kind,
            ));
        }
        Ok(result)
    }
}

pub(super) fn plan_transition(
    plan: &SubagentPlanV1,
    action: ReservationAction,
    parent_operation: Option<SubagentDigest>,
    cause_sha256: SubagentDigest,
) -> Result<SubagentReservationV1, AppError> {
    SubagentReservationV1::prepare(
        plan,
        None,
        0,
        action,
        ReservationPurpose::Plan,
        ReservationTransition {
            amount: plan.reservation,
            parent_operation,
            cause_sha256,
            accounting_audit_sha256: None,
        },
    )
    .map_err(|_| invalid())
}
