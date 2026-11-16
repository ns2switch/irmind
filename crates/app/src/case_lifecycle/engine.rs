use super::{
    CaseDeletedV1, CaseLifecycleError, CaseLifecycleStore, DeletionProgress, PreparedCaseDeletion,
    VerifiedCaseDeletion,
};
use crate::{AppError, CancellationToken, CaseId, CaseLock, Engine};
use std::sync::Arc;

impl Engine<'_> {
    #[must_use]
    pub fn with_case_lifecycle(mut self, store: Arc<dyn CaseLifecycleStore>) -> Self {
        self.case_lifecycle = Some(store);
        self
    }
    pub fn open_case_session(&self, id: &CaseId) -> Result<Option<Box<dyn CaseLock>>, AppError> {
        self.case_lifecycle
            .as_ref()
            .map(|s| s.open_session(id))
            .transpose()
    }
    pub fn prepare_case_deletion<'a>(
        &'a self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn PreparedCaseDeletion + 'a>, AppError> {
        self.require_attended_analyst("delete case")?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let store = self
            .case_lifecycle
            .as_ref()
            .ok_or(CaseLifecycleError::Unavailable)?;
        let prepared = store.prepare_deletion(id, cancel)?;
        self.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.audit_log.entries(id)?;
        let first = entries.first().ok_or(CaseLifecycleError::InvalidReceipt)?;
        let last = entries.last().ok_or(CaseLifecycleError::InvalidReceipt)?;
        let inventory = prepared.inventory();
        if inventory.case_id != *id
            || inventory.entry_count != entries.len() as u64
            || inventory.created_at != first.at
            || inventory.last_chain_hash != crate::hex(&last.hash)
        {
            return Err(CaseLifecycleError::InvalidReceipt.into());
        }
        self.verify_global_operations()?;
        Ok(prepared)
    }
    pub fn delete_prepared_case(
        &self,
        prepared: Box<dyn PreparedCaseDeletion + '_>,
        confirmation: &str,
        reason: Option<String>,
    ) -> Result<DeletionProgress, AppError> {
        self.require_attended_analyst("delete case")?;
        let inventory = prepared.inventory();
        if confirmation != inventory.case_id.as_str() && confirmation != inventory.title {
            return Err(CaseLifecycleError::Confirmation.into());
        }
        let receipt = CaseDeletedV1::new(inventory, reason, self.clock.now()?)?;
        let operation =
            self.sign_global_operation_at_unlocked(receipt.payload()?, receipt.deleted_at)?;
        prepared.commit(&operation)
    }
    pub fn deleted_cases(&self) -> Result<Vec<CaseDeletedV1>, AppError> {
        let entries = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&entries)?;
        entries
            .iter()
            .filter_map(|e| CaseDeletedV1::decode(e).transpose())
            .collect()
    }
    pub fn resume_case_deletions(
        &self,
        cancel: &CancellationToken,
    ) -> Result<Vec<DeletionProgress>, AppError> {
        self.require_attended_analyst("resume case deletion")?;
        let Some(store) = &self.case_lifecycle else {
            return Ok(Vec::new());
        };
        let entries = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&entries)?;
        let mut result = Vec::new();
        for operation in entries {
            if cancel.is_cancelled() {
                break;
            }
            if let Some(receipt) = CaseDeletedV1::decode(&operation)? {
                let id = receipt.inventory()?.case_id;
                let value = VerifiedCaseDeletion { operation, receipt };
                result.push(store.resume_deletion(&value, cancel).unwrap_or_else(|error| DeletionProgress {
                    case_id: id, complete: false, message: format!("Signed deletion pending: {error}. Inspect /cases deleted and retry.")
                }));
            }
        }
        Ok(result)
    }
}
