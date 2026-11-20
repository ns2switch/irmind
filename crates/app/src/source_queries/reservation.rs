use super::{
    SignedSourceQueryAdmission, SourceQueryAuthority, SourceQueryError, SourceQueryJournal,
};
use crate::{
    Actor, AppError, AuditEventKind, CancellationToken, CaseId, CaseScope, Engine, SignedEntry,
    Tool,
};

impl Engine<'_> {
    /// Record the reservation and the submit intent in the same transaction
    /// before handing authority to a source-query executor.
    pub fn persist_source_query_reservation(
        &self,
        case: &CaseId,
        admission: SignedSourceQueryAdmission<'_>,
        requires_policy_approval: bool,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("reserve source query resources")?;
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        let metadata = self.repo.get_case(case)?;
        if metadata.sealed {
            return Err(AppError::Sealed);
        }
        self.policy_for_case_unlocked(case)?
            .permits(&Tool::SourceQuery, self.completed_calls_unlocked(case)?)
            .map_err(|reason| AppError::Policy(reason.into()))?;
        let case_scope = CaseScope::parse(&metadata.scope).map_err(|_| SourceQueryError::Scope)?;
        let organization_scope = self.policy.scope.as_ref().ok_or(SourceQueryError::Scope)?;
        let agent = self
            .skills
            .as_ref()
            .ok_or(SourceQueryError::Unavailable)?
            .agent
            .actor();
        let Actor::Agent(principal) = agent else {
            return Err(SourceQueryError::Scope.into());
        };
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let mut entries = self.audit_log.entries(case)?;
        let contains = |entry: &crate::SignedEntry| {
            entry
                .seq
                .checked_sub(1)
                .and_then(|seq| usize::try_from(seq).ok())
                .and_then(|index| entries.get(index))
                .is_some_and(|stored| stored.hash == entry.hash)
        };
        if !contains(admission.plan)
            || admission.approval.is_some_and(|proof| !contains(proof))
            || !operations
                .iter()
                .any(|operation| operation.hash == admission.configuration.hash)
        {
            return Err(SourceQueryError::Approval.into());
        }
        let mut journal =
            SourceQueryJournal::replay(&entries, &operations, self.verifier.as_ref(), cancel)?;
        journal.broker.reserve_authenticated(
            admission,
            SourceQueryAuthority {
                principal: &principal,
                case_scope: &case_scope,
                organization_scope,
                requires_policy_approval,
                verifier: self.verifier.as_ref(),
            },
        )?;
        let last = entries.last().ok_or(AppError::InvalidChain(0))?;
        if last.seq.checked_add(1) != Some(admission.reservation.seq)
            || last.hash != admission.reservation.prev
        {
            return Err(AppError::InvalidChain(admission.reservation.seq));
        }
        let before = entries.len();
        entries.extend([admission.reservation.clone(), admission.intent.clone()]);
        // Replay also detects a duplicate, previously decided or stale plan.
        SourceQueryJournal::replay(&entries, &operations, self.verifier.as_ref(), cancel)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.audit_log.append_batch(&entries[before..])
    }

    /// Restore the durable hold before creating the page spool. The local
    /// budget and on-disk budget must both admit the capture.
    pub fn prepare_source_query_capture_spools(
        &self,
        case: &CaseId,
        reservation: &str,
        cancel: &CancellationToken,
    ) -> Result<
        (
            super::QueryCaptureWriter<tempfile::NamedTempFile>,
            tempfile::NamedTempFile,
        ),
        AppError,
    > {
        self.require_attended_analyst("prepare source query capture")?;
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        if self.repo.get_case(case)?.sealed {
            return Err(AppError::Sealed);
        }
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let entries = self.audit_log.entries(case)?;
        let journal =
            SourceQueryJournal::replay(&entries, &operations, self.verifier.as_ref(), cancel)?;
        let store = self
            .large_case_store
            .as_deref()
            .ok_or(SourceQueryError::Unavailable)?;
        journal
            .broker
            .prepare_capture_spools(reservation, self.audit_log.as_ref(), store, cancel)
    }

    /// Persist a provider observation against the durable intent. Unknown
    /// states remain held for reconciliation instead of granting a retry.
    pub fn persist_source_query_observation(
        &self,
        case: &CaseId,
        observation: &SignedEntry,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("record a source query execution")?;
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        if self.repo.get_case(case)?.sealed {
            return Err(AppError::Sealed);
        }
        if observation.kind != AuditEventKind::SourceQueryExecutionV1 {
            return Err(AppError::InvalidChain(observation.seq));
        }
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let mut entries = self.audit_log.entries(case)?;
        let last = entries.last().ok_or(AppError::InvalidChain(0))?;
        if last.seq.checked_add(1) != Some(observation.seq) || last.hash != observation.prev {
            return Err(AppError::InvalidChain(observation.seq));
        }
        entries.push(observation.clone());
        SourceQueryJournal::replay(&entries, &operations, self.verifier.as_ref(), cancel)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.audit_log.append(observation)
    }
}
