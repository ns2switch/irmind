use super::{
    AuditEventKind, CaseScope, PlanLedger, SubagentDigest, SubagentJournal, SubagentPlanV1,
    SubagentRecord, SubagentRecordError, SubagentResources,
};
use crate::subagents::{SubagentPlanContext, SubagentPolicySnapshot};

impl SubagentJournal {
    pub(crate) fn pending_task_scope(
        &self,
        task_id: SubagentDigest,
        tool: &crate::Tool,
        rules: &irmind_domain::PolicyRules,
        now: u64,
    ) -> Result<String, SubagentRecordError> {
        let state = self
            .plans
            .values()
            .find(|state| state.plan.tasks.iter().any(|task| task.task_id == task_id))
            .ok_or(SubagentRecordError)?;
        let task = state
            .plan
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .ok_or(SubagentRecordError)?;
        let scope = task.remote_scope.as_ref().ok_or(SubagentRecordError)?;
        let narrowed = CaseScope::parse(scope).map_err(|_| SubagentRecordError)?;
        if matches!(narrowed, CaseScope::LocalOnly)
            || self.failed
            || !state.is_open()
            || state.is_preview()
            || state.results.contains_key(&task_id)
            || now >= task.deadline_at
            || !narrowed.is_within(&self.scope)
            || rules
                .scope
                .as_ref()
                .is_some_and(|ceiling| !narrowed.is_within(ceiling))
            || serde_json::to_vec(&SubagentPolicySnapshot::new(rules)?)
                .map_err(|_| SubagentRecordError)?
                != serde_json::to_vec(&state.plan.policy).map_err(|_| SubagentRecordError)?
            || !self
                .types
                .get(&task.type_snapshot_sha256)
                .ok_or(SubagentRecordError)?
                .definition()
                .permits_tool(tool)
        {
            return Err(SubagentRecordError);
        }
        Ok(scope.clone())
    }
    pub(in crate::subagents) fn check_task_pending_owner(
        &self,
        checkpoint: &crate::subagents::SubagentCheckpointV1,
        actor: &crate::Actor,
    ) -> Result<
        (
            &crate::subagents::SubagentTaskSpec,
            &SubagentPlanV1,
            SubagentDigest,
        ),
        SubagentRecordError,
    > {
        if self.failed || self.agent.as_ref() != Some(actor) {
            return Err(SubagentRecordError);
        }
        for state in self.plans.values() {
            if let Some(task) = state
                .plan
                .tasks
                .iter()
                .find(|task| task.task_id == checkpoint.task_id)
            {
                let identity = checkpoint.identity()?;
                if !state
                    .checkpoints
                    .get(&task.task_id)
                    .into_iter()
                    .flatten()
                    .any(|signed| signed.identity().is_ok_and(|actual| actual == identity))
                {
                    return Err(SubagentRecordError);
                }
                return Ok((
                    task,
                    &state.plan,
                    state.allocation().ok_or(SubagentRecordError)?,
                ));
            }
        }
        Err(SubagentRecordError)
    }

    pub(in crate::subagents) fn release_transition(
        &self,
        started: &crate::subagents::StartedSubagentPlan,
    ) -> Result<crate::subagents::SubagentReservationV1, SubagentRecordError> {
        use crate::subagents::{
            ReservationAction, ReservationPurpose, ReservationTransition, SubagentReservationV1,
        };
        let state = self
            .plans
            .get(&started.plan.identity()?)
            .ok_or(SubagentRecordError)?;
        if self.failed
            || state.allocation() != Some(started.allocation.identity()?)
            || state.results.len() != started.plan.tasks.len()
        {
            return Err(SubagentRecordError);
        }
        let task = started.plan.tasks.last().ok_or(SubagentRecordError)?;
        let checkpoint = state
            .checkpoints
            .get(&task.task_id)
            .and_then(|checkpoints| checkpoints.last())
            .ok_or(SubagentRecordError)?;
        SubagentReservationV1::prepare(
            &started.plan,
            None,
            0,
            ReservationAction::ReleasePlan,
            ReservationPurpose::Plan,
            ReservationTransition {
                amount: started.plan.reservation.checked_sub(state.total_usage()?)?,
                parent_operation: Some(started.allocation.operation_id),
                cause_sha256: checkpoint.identity()?,
                accounting_audit_sha256: None,
            },
        )
    }

    pub(in crate::subagents) fn task_view(
        &self,
        started: &crate::subagents::StartedSubagentPlan,
        task_id: SubagentDigest,
        rules: &irmind_domain::PolicyRules,
    ) -> Result<crate::subagents::VerifiedTaskQueryView, SubagentRecordError> {
        let state = self
            .plans
            .get(&started.plan.identity()?)
            .ok_or(SubagentRecordError)?;
        let task = state
            .plan
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .ok_or(SubagentRecordError)?;
        if self.failed
            || !state.is_open()
            || state.is_preview()
            || state.allocation() != Some(started.allocation.identity()?)
            || state.plan.canonical()? != started.plan.canonical()?
            || state.results.contains_key(&task_id)
        {
            return Err(SubagentRecordError);
        }
        let policy_bytes = serde_json::to_vec(&SubagentPolicySnapshot::new(rules)?)
            .map_err(|_| SubagentRecordError)?;
        if policy_bytes
            != serde_json::to_vec(&state.plan.policy).map_err(|_| SubagentRecordError)?
        {
            return Err(SubagentRecordError);
        }
        let scope = task
            .remote_scope
            .as_deref()
            .map(CaseScope::parse)
            .transpose()
            .map_err(|_| SubagentRecordError)?
            .unwrap_or_else(|| state.case_scope.clone());
        if !scope.is_within(&self.scope)
            || rules
                .scope
                .as_ref()
                .is_some_and(|ceiling| !scope.is_within(ceiling))
        {
            return Err(SubagentRecordError);
        }
        let (generation_seq, generation_hash, sources) =
            self.task_source_generation(state, task)?;
        Ok(crate::subagents::VerifiedTaskQueryView {
            case: self.case.clone(),
            task: task_id,
            generation_seq,
            generation_hash,
            source_set: task.source_set_sha256,
            sources,
            scope,
            ceiling: rules.scope.clone(),
            policy_fingerprint: SubagentDigest::from_bytes(crate::sha256(&policy_bytes)),
        })
    }

    fn task_source_generation(
        &self,
        state: &PlanLedger,
        task: &crate::subagents::SubagentTaskSpec,
    ) -> Result<(u64, SubagentDigest, std::collections::BTreeSet<String>), SubagentRecordError>
    {
        let mut sources: std::collections::BTreeSet<_> = self
            .sets
            .get(&task.source_set_sha256)
            .ok_or(SubagentRecordError)?
            .iter()
            .map(|hash| crate::hex(hash.as_bytes()))
            .collect();
        let mut sequence = state.seq.checked_sub(1).ok_or(SubagentRecordError)?;
        let mut hash = state.plan.parent_checkpoint_sha256;
        for checkpoint in state.checkpoints.get(&task.task_id).into_iter().flatten() {
            if checkpoint.admitted_sources.is_empty() {
                continue;
            }
            let identity = checkpoint.identity()?;
            if !self.checkpoint_admissions.contains_key(&identity) {
                return Err(SubagentRecordError);
            }
            sequence = *self
                .checkpoint_sequences
                .get(&identity)
                .ok_or(SubagentRecordError)?;
            hash = *self
                .checkpoint_audit_hashes
                .get(&identity)
                .ok_or(SubagentRecordError)?;
            sources.extend(
                checkpoint
                    .admitted_sources
                    .iter()
                    .map(|hash| crate::hex(hash.as_bytes())),
            );
        }
        Ok((sequence, hash, sources))
    }

    pub(in crate::subagents) fn preparation_context(
        &self,
        turn: &str,
        rules: &irmind_domain::PolicyRules,
    ) -> Result<(u64, SubagentPlanContext), SubagentRecordError> {
        if self.failed
            || self.plans.values().any(PlanLedger::is_open)
            || self.closed_turns.contains(turn)
            || self.turn.as_ref().is_some_and(|prior| prior != turn)
        {
            return Err(SubagentRecordError);
        }
        let budget = self.budget.status(rules).map_err(|_| SubagentRecordError)?;
        let limits = budget
            .require_effective()
            .map_err(|_| SubagentRecordError)?;
        Ok((
            self.plans
                .values()
                .filter(|plan| plan.plan.turn_id == turn)
                .count() as u64
                + 1,
            SubagentPlanContext {
                parent_checkpoint_sha256: self.previous,
                budget_checkpoint_sha256: SubagentDigest::from_bytes(self.budget.checkpoint()),
                policy: SubagentPolicySnapshot::new(rules)?,
                case_limits: SubagentResources {
                    tokens: limits.model_tokens,
                    calls: limits.tool_calls,
                    rounds: rules.max_model_rounds_per_turn as u64,
                    cloud_bytes: limits.cloud_bytes,
                },
                usage: SubagentResources {
                    tokens: budget.usage.model_tokens,
                    calls: budget.usage.tool_calls,
                    rounds: self.rounds_used(turn)?,
                    cloud_bytes: budget.usage.cloud_bytes,
                },
                prior_reserved: self.outstanding_for_turn(Some(turn))?,
            },
        ))
    }

    pub(in crate::subagents) fn has_metadata<T: SubagentRecord>(
        &self,
        record: &T,
    ) -> Result<bool, SubagentRecordError> {
        let identity = record.identity()?;
        Ok(match T::KIND {
            AuditEventKind::SubagentSourcePageV1 => self.pages.contains_key(&identity),
            AuditEventKind::SubagentSourceSetV1 => self.sets.contains_key(&identity),
            AuditEventKind::SubagentTypeSnapshotV1 => self.types.contains_key(&identity),
            _ => return Err(SubagentRecordError),
        })
    }

    pub(in crate::subagents) fn preview_is_current(
        &self,
        plan: &SubagentPlanV1,
        rules: &irmind_domain::PolicyRules,
    ) -> Result<(), SubagentRecordError> {
        let state = self
            .plans
            .get(&plan.identity()?)
            .ok_or(SubagentRecordError)?;
        if self.failed
            || !state.is_preview()
            || state.plan.canonical()? != plan.canonical()?
            || self.budget.checkpoint() != *plan.budget_checkpoint_sha256.as_bytes()
            || SubagentPolicySnapshot::new(rules)?.rules()?.scope != plan.policy.rules()?.scope
            || SubagentPolicySnapshot::new(rules)?.limits()? != plan.policy.limits()?
            || serde_json::to_vec(&SubagentPolicySnapshot::new(rules)?)
                .map_err(|_| SubagentRecordError)?
                != serde_json::to_vec(&plan.policy).map_err(|_| SubagentRecordError)?
        {
            return Err(SubagentRecordError);
        }
        for task in &plan.tasks {
            if let Some(scope) = &task.remote_scope
                && !CaseScope::parse(scope)
                    .map_err(|_| SubagentRecordError)?
                    .is_within(&self.scope)
            {
                return Err(SubagentRecordError);
            }
        }
        Ok(())
    }
}

impl SubagentJournal {
    pub(in crate::subagents) fn task_method_tools(
        &self,
        started: &crate::subagents::StartedSubagentPlan,
        task_id: SubagentDigest,
        skills: &crate::SkillReceiptVerifier,
        compiler: &dyn crate::SkillCompiler,
        child_method: Option<crate::SkillSnapshotId>,
    ) -> Result<std::collections::BTreeSet<String>, SubagentRecordError> {
        let state = self
            .plans
            .get(&started.plan.identity()?)
            .ok_or(SubagentRecordError)?;
        let task = state
            .plan
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .ok_or(SubagentRecordError)?;
        self.task_view(started, task_id, &state.plan.policy.rules()?)?;
        let mut tools: std::collections::BTreeSet<_> = self
            .types
            .get(&task.type_snapshot_sha256)
            .ok_or(SubagentRecordError)?
            .definition()
            .tools()
            .iter()
            .cloned()
            .collect();
        if let Some(snapshot) = state.parent_skill {
            let (_, parent) = skills
                .snapshot_method(snapshot, state.seq, compiler)
                .map_err(|_| SubagentRecordError)?;
            tools.retain(|tool| parent.contains(tool));
        }
        if let Some(snapshot) = child_method {
            let (name, child) = skills
                .snapshot_method(snapshot, self.seq + 1, compiler)
                .map_err(|_| SubagentRecordError)?;
            if !self
                .types
                .get(&task.type_snapshot_sha256)
                .ok_or(SubagentRecordError)?
                .definition()
                .skills()
                .contains(&name)
            {
                return Err(SubagentRecordError);
            }
            tools.retain(|tool| child.contains(tool));
        } else if task.skill_snapshot_sha256.is_some() {
            tools.clear();
        }
        tools.insert("skill_read".into());
        Ok(tools)
    }
}
