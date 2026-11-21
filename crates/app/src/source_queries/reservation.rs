use super::{
    AdmittedSourceQuery, SignedSourceQueryAdmission, SourceQueryAuthority, SourceQueryError,
    SourceQueryExecutionV1, SourceQueryJournal, SourceQueryLeasePhase, SourceQueryPlanV1,
    SourceQueryReservationV1, SubmitObservationV1, admission::require_active_adoption,
    canonical_query_json,
};
use crate::{
    Actor, AppError, AuditEventKind, AuthorizedCall, CancellationToken, CaseId, CaseScope, Engine,
    SignedEntry, Tool,
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
        self.persist_source_query_reservation_unlocked(
            case,
            admission,
            requires_policy_approval,
            false,
            cancel,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn persist_source_query_reservation_unlocked(
        &self,
        case: &CaseId,
        admission: SignedSourceQueryAdmission<'_>,
        requires_policy_approval: bool,
        dispatch: bool,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
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
        let _global_lock = self.audit_log.lock_global_operations()?;
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let plan = SourceQueryPlanV1::decode(admission.plan.payload.as_bytes())?;
        require_active_adoption(&plan, &operations)?;
        let mut entries = self.audit_log.entries(case)?;
        if dispatch {
            self.check_live_query_allocation(&entries)?;
        }
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
        if dispatch {
            entries.push(self.signed_entry_after(
                case,
                entries.last(),
                crate::AuditOrigin::Policy,
                AuditEventKind::Allowed,
                Tool::SourceQuery.as_str(),
                None,
            )?);
        }
        // Replay also detects a duplicate, previously decided or stale plan.
        SourceQueryJournal::replay(&entries, &operations, self.verifier.as_ref(), cancel)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.audit_log.append_batch(&entries[before..])
    }

    /// Submit an already authorized, signed source-query plan. This is the
    /// acquisition boundary. The executor receives a lease only after the
    /// reservation and submit intent have committed together.
    pub fn submit_signed_source_query(
        &self,
        authorized: &AuthorizedCall,
        admission: SignedSourceQueryAdmission<'_>,
        cancel: &CancellationToken,
    ) -> Result<SubmitObservationV1, AppError> {
        crate::run_async(self.submit_signed_source_query_cancelable(authorized, admission, cancel))
    }

    pub async fn submit_signed_source_query_cancelable(
        &self,
        authorized: &AuthorizedCall,
        admission: SignedSourceQueryAdmission<'_>,
        cancel: &CancellationToken,
    ) -> Result<SubmitObservationV1, AppError> {
        self.require_attended_analyst("submit source query")?;
        let case = authorized.case_id();
        let plan = SourceQueryPlanV1::decode(admission.plan.payload.as_bytes())?;
        plan.check_authorized_call(authorized)?;
        let reservation =
            SourceQueryReservationV1::decode(admission.reservation.payload.as_bytes())?;
        let intent = SourceQueryExecutionV1::decode(admission.intent.payload.as_bytes())?;
        let executor = self
            .source_queries
            .as_ref()
            .ok_or(SourceQueryError::Unavailable)?
            .executor(plan.source().module())?;
        if executor.descriptor().version != plan.source().module_version()
            || executor.compile(plan.source(), plan.query())? != *plan.compiled()
        {
            return Err(SourceQueryError::Scope.into());
        }
        {
            let _lock = self.repo.lock_case(case)?;
            self.admit_signed_submission(authorized, admission, cancel)?;
        }
        let lease = AdmittedSourceQuery {
            case_id: case.clone(),
            plan: plan.content_id()?,
            attempt: plan.attempt,
            reservation: reservation.content_id()?,
            source: plan.source().clone(),
            compiled: plan.compiled().clone(),
            limits: plan.limits().clone(),
            execution_key: intent.execution_key().into(),
            phase: SourceQueryLeasePhase::Submit,
            execution: None,
        };
        let duration = std::time::Duration::from_secs(plan.limits().deadline_seconds);
        let observation = tokio::select! {
            biased;
            () = cancel.cancelled() => SubmitObservationV1::Unknown,
            reply = tokio::time::timeout(duration, executor.submit(&lease, cancel)) => match reply {
                Ok(Ok(SubmitObservationV1::Accepted(job))) if job.plan() == lease.plan() && job.attempt() == plan.attempt =>
                    SubmitObservationV1::Accepted(job),
                Ok(Ok(SubmitObservationV1::NotSubmitted)) => SubmitObservationV1::NotSubmitted,
                _ => SubmitObservationV1::Unknown,
            }
        };
        let active = self
            .skills
            .as_ref()
            .ok_or(SourceQueryError::Unavailable)?
            .agent
            .clone();
        let mut agent = self.local_handle();
        agent.signer = active;
        let elapsed =
            irmind_domain::IndexedTime::from_epoch_decimal(&agent.clock.now()?.to_string(), false)
                .map_err(|_| SourceQueryError::Invalid)?;
        let observed = intent.submit_observation(
            &observation,
            super::QueryTime::parse(&elapsed.to_rfc3339())?,
        )?;
        let payload = String::from_utf8(canonical_query_json(&observed)?)
            .map_err(|_| SourceQueryError::Invalid)?;
        let _lock = self.repo.lock_case(case)?;
        let previous = self
            .audit_log
            .last_entry(case)?
            .ok_or(AppError::InvalidChain(0))?;
        let frame = agent.signed_entry_after(
            case,
            Some(&previous),
            crate::AuditOrigin::Agent,
            AuditEventKind::SourceQueryExecutionV1,
            &payload,
            None,
        )?;
        // Cancellation must not erase an ambiguous outcome after durable intent.
        self.persist_source_query_observation_unlocked(case, &frame, &CancellationToken::new())?;
        Ok(observation)
    }

    fn admit_signed_submission(
        &self,
        authorized: &AuthorizedCall,
        admission: SignedSourceQueryAdmission<'_>,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let case = authorized.case_id();
        let current = self.repo.get_case(case)?;
        let rules = self.policy_for_case_unlocked(case)?;
        let gate = irmind_domain::evaluate_tainted_with_rules(
            &current,
            crate::Tainted::from_external(
                crate::ProposedCall {
                    tool: Tool::SourceQuery,
                    args: authorized.proposal_args().clone(),
                },
                crate::Provenance::new(admission.plan.hash, None, crate::SourceKind::ModelProposal),
            ),
            authorized.decision_seq(),
            self.mode,
            self.turn_has_detections(case)?,
            self.clock.now()?,
            &rules,
        );
        let requires_policy_approval = match gate {
            crate::Decision::Deny(reason) => return Err(AppError::Policy(reason.into())),
            crate::Decision::NeedsApproval(_) => true,
            crate::Decision::Allow(_) => false,
        };
        self.persist_source_query_reservation_unlocked(
            case,
            admission,
            requires_policy_approval,
            true,
            cancel,
        )
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
        self.persist_source_query_observation_unlocked(case, observation, cancel)
    }

    pub(super) fn persist_source_query_observation_unlocked(
        &self,
        case: &CaseId,
        observation: &SignedEntry,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
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
