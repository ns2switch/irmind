use crate::{
    Actor, AppError, AuditEventKind, AuditOrigin, CaseBudgetLimits, CaseBudgetStatus, CaseId,
    Engine, PolicyRules, SignedEntry,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetChange {
    version: u8,
    previous: Option<CaseBudgetLimits>,
    limits: CaseBudgetLimits,
    organization: CaseBudgetLimits,
    increase_confirmed: bool,
}

impl Engine<'_> {
    pub fn with_case_budget_defaults(mut self, limits: CaseBudgetLimits) -> Result<Self, AppError> {
        limits.validate()?;
        self.case_budget_defaults = Some(limits);
        Ok(self)
    }
    pub fn new_case_budget_limits(&self) -> CaseBudgetLimits {
        self.case_budget_defaults
            .unwrap_or_default()
            .intersection(CaseBudgetLimits::from_policy(&self.policy))
    }
    pub fn case_budget(&self, id: &CaseId) -> Result<CaseBudgetStatus, AppError> {
        let _lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        self.case_budget_unlocked(id)
    }
    pub(crate) fn case_budget_unlocked(&self, id: &CaseId) -> Result<CaseBudgetStatus, AppError> {
        budget_status(&self.audit_log.entries(id)?, &self.policy)
    }
    pub fn change_case_budget(
        &self,
        id: &CaseId,
        limits: CaseBudgetLimits,
        confirmed: bool,
    ) -> Result<bool, AppError> {
        self.require_attended_analyst("change case limits")?;
        limits.validate()?;
        let _lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        let status = self.case_budget_unlocked(id)?;
        if !limits.within(status.organization) {
            return Err(AppError::Policy("case limits exceed the organization ceiling; change policy.toml through the organization administrator".into()));
        }
        if !status.usage.fits(limits) {
            return Err(AppError::Policy(
                "case limits cannot be reduced below recorded consumption".into(),
            ));
        }
        if status.allocated.is_none_or(|old| limits.increases(old)) && !confirmed {
            return Err(AppError::Policy(
                "increasing case limits requires explicit analyst confirmation and signature"
                    .into(),
            ));
        }
        if Some(limits) == status.allocated {
            return Ok(false);
        }
        let payload = serde_json::to_string(&BudgetChange {
            version: 1,
            previous: status.allocated,
            limits,
            organization: status.organization,
            increase_confirmed: confirmed,
        })
        .map_err(|_| AppError::Policy("case budget cannot be encoded".into()))?;
        self.audit(
            id,
            AuditOrigin::Analyst,
            AuditEventKind::CaseBudgetChanged,
            &payload,
            None,
        )?;
        Ok(true)
    }
    pub(crate) fn policy_for_case_unlocked(&self, id: &CaseId) -> Result<PolicyRules, AppError> {
        let limits = self.case_budget_unlocked(id)?.require_effective()?;
        let mut policy = self.policy.clone();
        policy.max_model_tokens_per_case = limits.model_tokens;
        policy.max_tool_calls_per_case = usize::try_from(limits.tool_calls)
            .map_err(|_| AppError::Policy("invalid case call limit".into()))?;
        policy.max_object_bytes_per_case = limits.cloud_bytes;
        Ok(policy)
    }
}

/// Summarizes an authenticated current-format chain; signature verification is the caller's responsibility.
pub fn budget_status(
    entries: &[SignedEntry],
    organization: &PolicyRules,
) -> Result<CaseBudgetStatus, AppError> {
    let first = entries.first().ok_or(AppError::InvalidChain(0))?;
    let created: super::CaseCreatedEvent =
        serde_json::from_str(&first.payload).map_err(|_| AppError::InvalidChain(first.seq))?;
    if first.kind != AuditEventKind::CaseCreated
        || first.actor != Actor::Analyst
        || created.version != 3
    {
        return Err(AppError::InvalidChain(first.seq));
    }
    let mut allocated = created.budget;
    if let Some(limits) = allocated {
        limits.validate()?;
    }
    let mut ledger = crate::case_budget::UsageAccumulator::default();
    for entry in entries {
        if entry.kind != AuditEventKind::CaseBudgetChanged {
            ledger.push(entry)?;
            continue;
        }
        let change: BudgetChange =
            serde_json::from_str(&entry.payload).map_err(|_| AppError::InvalidChain(entry.seq))?;
        if entry.actor != Actor::Analyst
            || change.version != 1
            || serde_json::to_string(&change).ok().as_deref() != Some(entry.payload.as_str())
            || change.previous != allocated
            || change.limits.validate().is_err()
            || change.organization.validate().is_err()
            || !change.limits.within(change.organization)
            || !ledger.finish().fits(change.limits)
            || (allocated.is_none_or(|old| change.limits.increases(old))
                && !change.increase_confirmed)
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        allocated = Some(change.limits);
    }
    let ceiling = CaseBudgetLimits::from_policy(organization);
    Ok(CaseBudgetStatus {
        allocated,
        organization: ceiling,
        effective: allocated.map(|limits| limits.intersection(ceiling)),
        usage: ledger.finish(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn case_budget_receipt_has_canonical_current_format_golden_bytes() {
        let limits = CaseBudgetLimits::default();
        let change = BudgetChange {
            version: 1,
            previous: Some(limits),
            limits: CaseBudgetLimits {
                model_tokens: 3_000_000,
                tool_calls: 2_000,
                ..limits
            },
            organization: CaseBudgetLimits {
                model_tokens: 10_000_000,
                tool_calls: 10_000,
                cloud_bytes: 10_995_116_277_760,
            },
            increase_confirmed: true,
        };
        let encoded = serde_json::to_string(&change).unwrap();
        assert_eq!(
            encoded,
            include_str!("../../tests/fixtures/case-budget-v1.json")
        );
        assert_eq!(
            crate::hex(&crate::sha256(encoded.as_bytes())),
            include_str!("../../tests/fixtures/case-budget-v1.sha256").trim()
        );
        let initial = BudgetChange {
            previous: None,
            limits: CaseBudgetLimits::default(),
            ..change
        };
        let initial = serde_json::to_string(&initial).unwrap();
        assert_eq!(
            initial,
            include_str!("../../tests/fixtures/case-budget-initial-v1.json")
        );
        assert_eq!(
            crate::hex(&crate::sha256(initial.as_bytes())),
            include_str!("../../tests/fixtures/case-budget-initial-v1.sha256").trim()
        );
    }
}
