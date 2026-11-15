use super::{
    AuditEventKind, CaseScope, PlanLedger, SubagentDigest, SubagentJournal, SubagentPlanV1,
    SubagentRecord, SubagentRecordError, SubagentResources,
};
use crate::subagents::{SubagentPlanContext, SubagentPolicySnapshot};

impl SubagentJournal {
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
