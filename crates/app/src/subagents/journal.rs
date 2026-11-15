//! Streaming validation of authenticated plan metadata. Data is not a task lease.
use super::{
    SubagentDigest, SubagentPlanV1, SubagentRecord, SubagentRecordError, SubagentResources,
    SubagentSourcePageV1, SubagentSourceSetV1, SubagentTypeSnapshotV1,
};
use crate::{Actor, AppError, AuditEventKind, CaseId, CaseScope, SignedEntry, Verifier};
use std::collections::{BTreeMap, BTreeSet};

mod accounting;
mod ledger;
mod material;
mod preparation;
pub use accounting::TaskDispatchAttribution;
use ledger::PlanLedger;
pub use material::BranchMaterialVerifier;

pub struct SubagentJournal {
    case: CaseId,
    agent: Option<Actor>,
    seq: u64,
    previous: SubagentDigest,
    failed: bool,
    budget: crate::engine::BudgetReplay,
    scope: CaseScope,
    sources: BTreeSet<SubagentDigest>,
    pages: BTreeMap<SubagentDigest, SubagentSourcePageV1>,
    sets: BTreeMap<SubagentDigest, Vec<SubagentDigest>>,
    types: BTreeMap<SubagentDigest, SubagentTypeSnapshotV1>,
    plans: BTreeMap<SubagentDigest, PlanLedger>,
    tasks: BTreeSet<SubagentDigest>,
    nonces: BTreeSet<String>,
    references: usize,
    accounting: BTreeMap<SubagentDigest, accounting::Accounted>,
    accounted: BTreeSet<(SubagentDigest, super::ReservationPurpose)>,
    checkpoint_sequences: BTreeMap<SubagentDigest, u64>,
    parent_rounds: u64,
    parent_skill: Option<(String, crate::SkillSnapshotId)>,
    turn: Option<String>,
    closed_turns: BTreeSet<String>,
}
impl SubagentJournal {
    pub fn new(case: CaseId, agent: Actor) -> Result<Self, SubagentRecordError> {
        if !matches!(agent, Actor::Agent(_)) {
            return Err(SubagentRecordError);
        }
        Ok(Self {
            case,
            agent: Some(agent),
            seq: 0,
            previous: SubagentDigest::from_bytes([0; 32]),
            failed: false,
            budget: crate::engine::BudgetReplay::default(),
            scope: CaseScope::LocalOnly,
            sources: BTreeSet::new(),
            pages: BTreeMap::new(),
            sets: BTreeMap::new(),
            types: BTreeMap::new(),
            plans: BTreeMap::new(),
            tasks: BTreeSet::new(),
            nonces: BTreeSet::new(),
            references: 0,
            accounting: BTreeMap::new(),
            accounted: BTreeSet::new(),
            checkpoint_sequences: BTreeMap::new(),
            parent_rounds: 0,
            parent_skill: None,
            turn: None,
            closed_turns: BTreeSet::new(),
        })
    }

    /// Offline replay binds the Agent only from an authenticated subagent entry.
    /// The enclosing sealed main chain authenticates that binding. This state
    /// creates no signer, task lease or execution capability.
    pub fn for_verification(case: CaseId) -> Result<Self, SubagentRecordError> {
        let mut journal = Self::new(
            case,
            Actor::Agent(
                irmind_domain::AgentId::parse("unbound").map_err(|_| SubagentRecordError)?,
            ),
        )?;
        journal.agent = None;
        Ok(journal)
    }

    pub fn has_open_plans(&self) -> Result<bool, SubagentRecordError> {
        if self.failed {
            return Err(SubagentRecordError);
        }
        Ok(self.plans.values().any(PlanLedger::is_open))
    }

    /// Every entry, including ordinary accounting, must arrive in main-chain order.
    /// A failed replay is poisoned and cannot be reused as verified state.
    pub fn accept(&mut self, entry: &SignedEntry, verifier: &dyn Verifier) -> Result<(), AppError> {
        if self.failed {
            return Err(AppError::InvalidChain(entry.seq));
        }
        let result = self.accept_inner(entry, verifier);
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(|_| AppError::InvalidChain(entry.seq))
    }

    fn accept_inner(
        &mut self,
        entry: &SignedEntry,
        verifier: &dyn Verifier,
    ) -> Result<(), SubagentRecordError> {
        if entry.case_id != self.case.as_str()
            || self.seq.checked_add(1) != Some(entry.seq)
            || self.previous.as_bytes() != &entry.prev
            || crate::sha256(&entry.canonical()) != entry.hash
            || verifier
                .trusted_public_key(&entry.actor)
                .map_err(|_| SubagentRecordError)?
                != entry.public_key
        {
            return Err(SubagentRecordError);
        }
        verifier
            .verify(&entry.public_key, &entry.hash, &entry.sig)
            .map_err(|_| SubagentRecordError)?;
        if is_subagent_kind(entry.kind) {
            if self.agent.is_none() && entry.kind != AuditEventKind::SubagentPlanApprovalV1 {
                if !matches!(entry.actor, Actor::Agent(_)) {
                    return Err(SubagentRecordError);
                }
                self.agent = Some(entry.actor.clone());
            }
            let expected = if entry.kind == AuditEventKind::SubagentPlanApprovalV1 {
                &Actor::Analyst
            } else {
                self.agent.as_ref().ok_or(SubagentRecordError)?
            };
            if entry.evidence.is_some() || &entry.actor != expected {
                return Err(SubagentRecordError);
            }
        }
        if entry.kind == AuditEventKind::CaseSealed && self.has_open_plans()? {
            return Err(SubagentRecordError);
        }
        self.accept_metadata(entry)?;
        self.observe_accounting(entry)?;
        self.budget.accept(entry).map_err(|_| SubagentRecordError)?;
        if entry.kind == AuditEventKind::CaseBudgetChanged {
            let status = self
                .budget
                .status(&irmind_domain::PolicyRules::default())
                .map_err(|_| SubagentRecordError)?;
            let limits = status.allocated.ok_or(SubagentRecordError)?;
            let held = self.outstanding()?;
            if status
                .usage
                .model_tokens
                .checked_add(held.tokens)
                .is_none_or(|used| used > limits.model_tokens)
                || status
                    .usage
                    .tool_calls
                    .checked_add(held.calls)
                    .is_none_or(|used| used > limits.tool_calls)
                || status
                    .usage
                    .cloud_bytes
                    .checked_add(held.cloud_bytes)
                    .is_none_or(|used| used > limits.cloud_bytes)
            {
                return Err(SubagentRecordError);
            }
        }
        self.seq = entry.seq;
        self.previous = SubagentDigest::from_bytes(entry.hash);
        Ok(())
    }

    fn accept_metadata(&mut self, entry: &SignedEntry) -> Result<(), SubagentRecordError> {
        match entry.kind {
            AuditEventKind::Prompt => {
                if self.plans.values().any(PlanLedger::is_open) {
                    return Err(SubagentRecordError);
                }
                if let Some(turn) = self.turn.take() {
                    self.closed_turns.insert(turn);
                }
                self.parent_rounds = 0;
                self.parent_skill = None;
            }
            AuditEventKind::ModelRequest if entry.actor == Actor::Analyst => {
                self.parent_rounds = self
                    .parent_rounds
                    .checked_add(1)
                    .ok_or(SubagentRecordError)?;
            }
            AuditEventKind::SkillLoadV1 => {
                let load =
                    crate::SkillLoadV1::decode(&entry.payload).map_err(|_| SubagentRecordError)?;
                if load.result() == crate::SkillLoadResult::Loaded {
                    self.parent_skill = Some((
                        load.turn().into(),
                        load.snapshot().map_err(|_| SubagentRecordError)?,
                    ));
                }
            }
            AuditEventKind::CaseCreated | AuditEventKind::CaseScopeChanged => {
                #[derive(serde::Deserialize)]
                struct Scope {
                    #[serde(alias = "new_scope")]
                    scope: String,
                }
                let scope: Scope =
                    serde_json::from_str(&entry.payload).map_err(|_| SubagentRecordError)?;
                self.scope = CaseScope::parse(&scope.scope).map_err(|_| SubagentRecordError)?;
            }
            AuditEventKind::SourceManifestV2 => {
                let source = irmind_domain::SourceManifestV2::decode(&entry.payload)
                    .map_err(|_| SubagentRecordError)?;
                self.sources
                    .insert(SubagentDigest::parse(source.source.sha256.as_str())?);
            }
            AuditEventKind::SubagentSourcePageV1 => self.page(decode_entry(entry)?)?,
            AuditEventKind::SubagentSourceSetV1 => self.source_set(&decode_entry(entry)?)?,
            AuditEventKind::SubagentTypeSnapshotV1 => {
                let value: SubagentTypeSnapshotV1 = decode_entry(entry)?;
                if value.case_id() != self.case.as_str()
                    || self.types.len() >= 6
                    || self.types.insert(value.identity()?, value).is_some()
                {
                    return Err(SubagentRecordError);
                }
            }
            AuditEventKind::SubagentPlanV1 => self.plan(decode_entry(entry)?, entry)?,
            AuditEventKind::SubagentPlanApprovalV1
            | AuditEventKind::SubagentReservationV1
            | AuditEventKind::SubagentCheckpointV1
            | AuditEventKind::SubagentResultV1 => self.plan_transition(entry)?,
            _ => {}
        }
        Ok(())
    }

    fn page(&mut self, value: SubagentSourcePageV1) -> Result<(), SubagentRecordError> {
        if value.case_id() != self.case.as_str()
            || self.pages.len() >= 16_384
            || value
                .sources()
                .iter()
                .any(|hash| !self.sources.contains(hash))
            || self.pages.insert(value.identity()?, value).is_some()
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }

    fn source_set(&mut self, value: &SubagentSourceSetV1) -> Result<(), SubagentRecordError> {
        let pages = value
            .pages()
            .iter()
            .map(|hash| self.pages.get(hash).cloned().ok_or(SubagentRecordError))
            .collect::<Result<Vec<_>, _>>()?;
        value.verify_pages(&pages)?;
        self.references = self
            .references
            .checked_add(usize::try_from(value.count()).map_err(|_| SubagentRecordError)?)
            .ok_or(SubagentRecordError)?;
        let sources = pages
            .into_iter()
            .flat_map(|p| p.sources().to_vec())
            .collect();
        if value.case_id() != self.case.as_str()
            || self.sets.len() >= 256
            || self.references > 65_536
            || self.sets.insert(value.identity()?, sources).is_some()
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }

    fn plan(
        &mut self,
        plan: SubagentPlanV1,
        entry: &SignedEntry,
    ) -> Result<(), SubagentRecordError> {
        let rules = plan.policy.rules()?;
        let budget = self
            .budget
            .status(&rules)
            .map_err(|_| SubagentRecordError)?;
        let effective = budget
            .require_effective()
            .map_err(|_| SubagentRecordError)?;
        let limits = SubagentResources {
            tokens: effective.model_tokens,
            calls: effective.tool_calls,
            rounds: rules.max_model_rounds_per_turn as u64,
            cloud_bytes: effective.cloud_bytes,
        };
        if plan.case_id != self.case.as_str()
            || self.plans.values().any(PlanLedger::is_preview)
            || self.tasks.len() + plan.tasks.len() > 256
            || plan.parent_checkpoint_sha256 != self.previous
            || plan.budget_checkpoint_sha256.as_bytes() != &self.budget.checkpoint()
            || plan.case_limits != limits
            || entry.at > plan.deadline_at
            || plan.usage.tokens != budget.usage.model_tokens
            || plan.usage.calls != budget.usage.tool_calls
            || plan.usage.cloud_bytes != budget.usage.cloud_bytes
            || plan.usage.rounds != self.rounds_used(&plan.turn_id)?
            || plan.prior_reserved != self.outstanding_for_turn(Some(&plan.turn_id))?
            || self.plans.contains_key(&plan.identity()?)
            || self.turn.as_ref().is_some_and(|turn| turn != &plan.turn_id)
            || self.closed_turns.contains(&plan.turn_id)
            || plan.ordinal
                != self
                    .plans
                    .values()
                    .filter(|p| p.plan.turn_id == plan.turn_id)
                    .count() as u64
                    + 1
        {
            return Err(SubagentRecordError);
        }
        for task in &plan.tasks {
            if !self.sets.contains_key(&task.source_set_sha256)
                || !self.types.contains_key(&task.type_snapshot_sha256)
                || !self.tasks.insert(task.task_id)
                || !self.nonces.insert(task.nonce.clone())
            {
                return Err(SubagentRecordError);
            }
            if let Some(scope) = &task.remote_scope {
                let scope = CaseScope::parse(scope).map_err(|_| SubagentRecordError)?;
                if !scope.is_within(&self.scope)
                    || rules
                        .scope
                        .as_ref()
                        .is_some_and(|ceiling| !scope.is_within(ceiling))
                {
                    return Err(SubagentRecordError);
                }
            }
        }
        self.turn = Some(plan.turn_id.clone());
        let parent_skill = self
            .parent_skill
            .as_ref()
            .filter(|(turn, _)| turn == &plan.turn_id)
            .map(|(_, skill)| *skill);
        self.plans.insert(
            plan.identity()?,
            PlanLedger::new(
                plan,
                SubagentDigest::from_bytes(entry.hash),
                entry.seq,
                parent_skill,
            ),
        );
        Ok(())
    }

    pub fn outstanding(&self) -> Result<SubagentResources, SubagentRecordError> {
        if self.failed {
            return Err(SubagentRecordError);
        }
        self.outstanding_for_turn(self.turn.as_deref())
    }
    fn outstanding_for_turn(
        &self,
        turn: Option<&str>,
    ) -> Result<SubagentResources, SubagentRecordError> {
        self.plans
            .values()
            .try_fold(SubagentResources::default(), |total, plan| {
                let mut held = plan.outstanding()?;
                if turn != Some(plan.plan.turn_id.as_str()) {
                    held.rounds = 0;
                }
                total.checked_add(held)
            })
    }
    fn rounds_used(&self, turn: &str) -> Result<u64, SubagentRecordError> {
        self.plans
            .values()
            .filter(|plan| plan.plan.turn_id == turn)
            .try_fold(self.parent_rounds, |total, plan| {
                total
                    .checked_add(plan.turn_usage()?.rounds)
                    .ok_or(SubagentRecordError)
            })
    }
}

pub fn is_subagent_kind(kind: AuditEventKind) -> bool {
    matches!(
        kind,
        AuditEventKind::SubagentSourcePageV1
            | AuditEventKind::SubagentSourceSetV1
            | AuditEventKind::SubagentTypeSnapshotV1
            | AuditEventKind::SubagentPlanV1
            | AuditEventKind::SubagentPlanApprovalV1
            | AuditEventKind::SubagentReservationV1
            | AuditEventKind::SubagentCheckpointV1
            | AuditEventKind::SubagentResultV1
    )
}
pub(super) fn decode_entry<T: SubagentRecord>(
    entry: &SignedEntry,
) -> Result<T, SubagentRecordError> {
    let (label, encoded) = entry.payload.split_once(':').ok_or(SubagentRecordError)?;
    if entry.kind != T::KIND || label != T::KIND.as_str() || encoded.len() > 512 * 1024 {
        return Err(SubagentRecordError);
    }
    let bytes = hex::decode(encoded).map_err(|_| SubagentRecordError)?;
    if crate::hex(&bytes) != encoded {
        return Err(SubagentRecordError);
    }
    T::decode(&bytes)
}
