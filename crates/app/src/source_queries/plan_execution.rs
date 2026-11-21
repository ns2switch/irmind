use super::{
    AcquiredSourceQuery, SignedSourceQueryAdmission, SourceQueryApprovalV1, SourceQueryError,
    SourceQueryExecutionV1, SourceQueryPlanV1, SourceQueryReservationV1,
    acquisition::query_payload,
    admission::{active_source_adoption, adopted_threshold},
};
use crate::{
    AppError, AuditEventKind, AuditOrigin, AuthorizedCall, CancellationToken, CaseId, Engine,
    SignedEntry, SignedOperation,
};

struct ExecutionProofs {
    call: AuthorizedCall,
    plan: SignedEntry,
    approval: Option<SignedEntry>,
    reservation: SignedEntry,
    intent: SignedEntry,
    operation: SignedOperation,
}

impl Engine<'_> {
    pub fn source_query_plan_text(
        &self,
        case: &CaseId,
        plan_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        let entries = self.audit_log.entries(case)?;
        let (frame, _) = lookup_plan(&entries, plan_id)?;
        // This may include literal model filters. Use the ordinary content
        // guard before showing those to the analyst.
        Ok(self.guard.screen(&frame.payload)?.text)
    }

    pub fn run_source_query_plan_blocking(
        &self,
        case: &CaseId,
        plan_id: &str,
        approval_reason: &str,
        cancel: &CancellationToken,
    ) -> Result<AcquiredSourceQuery, AppError> {
        crate::run_async(self.run_source_query_plan(case, plan_id, Some(approval_reason), cancel))
    }

    /// Execute a committed plan after the attended interaction supplies its
    /// explicit reason where query-specific consent is required.
    pub async fn run_source_query_plan(
        &self,
        case: &CaseId,
        plan_id: &str,
        approval_reason: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<AcquiredSourceQuery, AppError> {
        self.require_attended_analyst("run a source-query plan")?;
        let proof = self.prepare_execution_proofs(case, plan_id, approval_reason, cancel)?;
        self.acquire_signed_source_query_cancelable(
            &proof.call,
            SignedSourceQueryAdmission {
                plan: &proof.plan,
                approval: proof.approval.as_ref(),
                reservation: &proof.reservation,
                intent: &proof.intent,
                configuration: &proof.operation,
            },
            cancel,
        )
        .await
    }

    fn prepare_execution_proofs(
        &self,
        case: &CaseId,
        plan_id: &str,
        reason: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<ExecutionProofs, AppError> {
        if !super::types::digest(plan_id) {
            return Err(SourceQueryError::Invalid.into());
        }
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        let entries = self.audit_log.entries(case)?;
        let metadata = self.repo.get_case(case)?;
        let mut last = entries.last().ok_or(AppError::InvalidChain(0))?;
        let (plan_frame, plan) = lookup_plan(&entries, plan_id)?;
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let adoption = active_source_adoption(plan.source(), &operations)?;
        let threshold = adopted_threshold(&plan, adoption.operation, self.verifier.as_ref())?;
        let authorized = match irmind_domain::evaluate_with_rules(
            &metadata,
            plan.proposal()?,
            last.seq.checked_add(1).ok_or(SourceQueryError::Limit)?,
            self.mode,
            self.clock.now()?,
            &self.policy_for_case_unlocked(case)?,
        ) {
            crate::Decision::Allow(call) => call,
            crate::Decision::Deny(reason) => return Err(AppError::Policy(reason.into())),
            crate::Decision::NeedsApproval(_) => return Err(SourceQueryError::Approval.into()),
        };
        let at = self.query_now()?;
        let existing = existing_approval(&entries, plan_id)?;
        let approval =
            self.confirm_query_plan(case, plan_id, &plan, last, reason, existing, threshold)?;
        if let Some((frame, _)) = &approval
            && frame.seq > last.seq
        {
            last = frame;
        }
        let reservation = SourceQueryReservationV1::for_plan(
            &plan,
            approval.as_ref().map(|(_, value)| value),
            at.clone(),
        )?;
        let intent = SourceQueryExecutionV1::intent_for_plan(case, &plan, &reservation, at)?;
        let reservation = self.sign_query_frame(
            case,
            Some(last),
            AuditEventKind::SourceQueryReservationV1,
            &reservation,
        )?;
        let intent = self.sign_query_frame(
            case,
            Some(&reservation),
            AuditEventKind::SourceQueryExecutionV1,
            &intent,
        )?;
        Ok(ExecutionProofs {
            call: authorized,
            plan: plan_frame.clone(),
            approval: approval.map(|(frame, _)| frame),
            reservation,
            intent,
            operation: adoption.operation.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn confirm_query_plan(
        &self,
        case: &CaseId,
        plan_id: &str,
        plan: &SourceQueryPlanV1,
        last: &SignedEntry,
        reason: Option<&str>,
        existing: Option<(SignedEntry, SourceQueryApprovalV1)>,
        threshold: u64,
    ) -> Result<Option<(SignedEntry, SourceQueryApprovalV1)>, AppError> {
        if let Some((frame, value)) = existing {
            if !value.permits(plan, plan_id) {
                return Err(SourceQueryError::Approval.into());
            }
            return Ok(Some((frame, value)));
        }
        let Some(reason) = reason else {
            return if plan.requires_approval(threshold, false) {
                Err(SourceQueryError::Approval.into())
            } else {
                Ok(None)
            };
        };
        let approval = SourceQueryApprovalV1::approve_plan(plan, reason, self.query_now()?)?;
        let frame = self.signed_entry_after(
            case,
            Some(last),
            AuditOrigin::Analyst,
            AuditEventKind::SourceQueryApprovalV1,
            &query_payload(&approval)?,
            None,
        )?;
        self.audit_log.append(&frame)?;
        Ok(Some((frame, approval)))
    }
}

fn lookup_plan<'a>(
    entries: &'a [SignedEntry],
    id: &str,
) -> Result<(&'a SignedEntry, SourceQueryPlanV1), AppError> {
    for frame in entries
        .iter()
        .rev()
        .filter(|entry| entry.kind == AuditEventKind::SourceQueryPlanV1)
    {
        let plan = SourceQueryPlanV1::decode(frame.payload.as_bytes())?;
        if plan.content_id()? == id {
            return Ok((frame, plan));
        }
    }
    Err(SourceQueryError::Invalid.into())
}

fn existing_approval(
    entries: &[SignedEntry],
    id: &str,
) -> Result<Option<(SignedEntry, SourceQueryApprovalV1)>, AppError> {
    for frame in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SourceQueryApprovalV1)
    {
        let approval = SourceQueryApprovalV1::decode(frame.payload.as_bytes())?;
        if approval.plan() == id {
            return Ok(Some((frame.clone(), approval)));
        }
    }
    Ok(None)
}
