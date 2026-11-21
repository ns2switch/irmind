use super::{
    BudgetReplay, SourceQueryAllocationV1, SourceQueryError, SourceQueryJournal,
    SourceQueryResources, acquisition::query_payload,
};
use crate::{
    AppError, AuditEventKind, AuditOrigin, CancellationToken, CaseId, Engine, SignedEntry,
    engine::current_case_creation,
};

#[derive(Clone, Copy, Debug)]
pub struct SourceQueryBudgetStatus {
    pub revision: u64,
    pub allocation: SourceQueryAllocationV1,
    pub organization: Option<SourceQueryAllocationV1>,
    pub used: SourceQueryResources,
    pub held: SourceQueryResources,
}

impl Engine<'_> {
    pub fn source_query_budget(
        &self,
        case: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<SourceQueryBudgetStatus, AppError> {
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        let entries = self.audit_log.entries(case)?;
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let budget = replay_budget(&entries)?;
        let (revision, allocation) = budget.current();
        let journal =
            SourceQueryJournal::replay(&entries, &operations, self.verifier.as_ref(), cancel)?;
        Ok(SourceQueryBudgetStatus {
            revision,
            allocation,
            organization: self.source_query_organization_ceiling(),
            used: journal.used(),
            held: journal.held(),
        })
    }

    pub fn change_source_query_budget(
        &self,
        case: &CaseId,
        allocation: SourceQueryAllocationV1,
        reason: &str,
        cancel: &CancellationToken,
    ) -> Result<bool, AppError> {
        self.require_attended_analyst("change case source-query limits")?;
        let ceiling = self
            .source_query_organization_ceiling()
            .ok_or(SourceQueryError::Disabled)?;
        if !allocation.within(ceiling) {
            return Err(SourceQueryError::Budget.into());
        }
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        if self.repo.get_case(case)?.sealed {
            return Err(AppError::Sealed);
        }
        let entries = self.audit_log.entries(case)?;
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let budget = replay_budget(&entries)?;
        let (revision, current) = budget.current();
        if current == allocation {
            return Ok(false);
        }
        let mut journal =
            SourceQueryJournal::replay(&entries, &operations, self.verifier.as_ref(), cancel)?;
        journal.broker.change_allocation(
            revision.checked_add(1).ok_or(SourceQueryError::Limit)?,
            allocation,
        )?;
        let record = budget.next(allocation, reason, self.query_now()?)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.audit(
            case,
            AuditOrigin::Analyst,
            AuditEventKind::SourceQueryBudgetV1,
            &query_payload(&record)?,
            None,
        )?;
        Ok(true)
    }

    pub(super) fn source_query_organization_ceiling(&self) -> Option<SourceQueryAllocationV1> {
        self.source_queries.as_ref()?.organization_ceiling
    }

    pub(super) fn check_live_query_allocation(
        &self,
        entries: &[SignedEntry],
    ) -> Result<(), AppError> {
        let Some(ceiling) = self.source_query_organization_ceiling() else {
            return Err(SourceQueryError::Disabled.into());
        };
        if !replay_budget(entries)?.current().1.within(ceiling) {
            return Err(SourceQueryError::Budget.into());
        }
        Ok(())
    }
}

fn replay_budget(entries: &[SignedEntry]) -> Result<BudgetReplay<'_>, AppError> {
    let (first, rest) = entries.split_first().ok_or(AppError::InvalidChain(0))?;
    let mut budget = BudgetReplay::new(first, current_case_creation(first)?.source_queries);
    for entry in rest {
        budget.accept(entry)?;
    }
    Ok(budget)
}
