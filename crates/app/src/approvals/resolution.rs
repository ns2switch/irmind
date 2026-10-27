use super::{AnalystVerifierAdapter, ApprovalEvent, ApprovalRequest, PendingEvent};
use crate::{
    Actor, AnalystApprovalVerifier, AppError, AuthorizedCall, BTreeMap, CancellationToken, Case,
    CaseId, Decision, Engine, ExecutionMode, PendingApproval, ProposedCall, SignedEntry, hex,
    sha256,
};

impl Engine<'_> {
    pub fn edit_approval(
        &self,
        id: &CaseId,
        request_id: &str,
        new_args: BTreeMap<String, String>,
    ) -> Result<String, AppError> {
        self.require_attended_analyst("edit approval")?;
        let _case_lock = self.repo.lock_case(id)?;
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        let request = self
            .pending_requests_unlocked(&case, &self.audit_log.entries(id)?)?
            .into_iter()
            .find(|request| request.id == request_id)
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyPendingApprovalNotFound,
            ))?;
        let proposal = ProposedCall {
            tool: request.tool.clone(),
            args: new_args,
        };
        self.policy
            .permits(&proposal.tool, 0)
            .map_err(|reason| AppError::Policy(reason.into()))?;
        let last = self
            .audit_log
            .last_entry(id)?
            .ok_or(AppError::InvalidChain(0))?;
        let decision_seq = last.seq.checked_add(3).ok_or(AppError::Fixed(
            crate::FixedAppError::StorageAuditSequenceOverflow,
        ))?;
        let Decision::NeedsApproval(replacement) = irmind_domain::evaluate_with_rules(
            &case,
            proposal.clone(),
            decision_seq,
            request.mode,
            self.clock.now()?,
            &self.policy,
        ) else {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyEditedArgumentsDoNotProduceAPendingApproval,
            ));
        };
        let replacement_id = hex(&sha256(&replacement.challenge()));
        self.supersede_approval(id, &request, &proposal, &replacement_id)?;
        let stored_id = self.audit_pending(id, &replacement, request.mode)?;
        if stored_id != replacement_id {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyEditedRequestIdMismatch,
            ));
        }
        Ok(format!(
            "edited request pending: {replacement_id}; no tool was executed"
        ))
    }

    fn supersede_approval(
        &self,
        id: &CaseId,
        request: &ApprovalRequest,
        proposal: &ProposedCall,
        replacement_id: &str,
    ) -> Result<(), AppError> {
        let case = self.repo.get_case(id)?;
        let old = PendingApproval::recover_with_rules(
            &case,
            request.mode,
            &request.challenge,
            self.clock.now()?,
            &self.policy,
        )
        .map_err(|_| {
            AppError::Fixed(crate::FixedAppError::PolicyStoredApprovalChallengeIsInvalid)
        })?;
        let signature = self.signer.sign(&old.rejection_challenge())?;
        old.reject(&signature, &AnalystVerifierAdapter(self.verifier.as_ref()))
            .map_err(|_| {
                AppError::Fixed(crate::FixedAppError::SignatureAnalystDenialSignatureIsInvalid)
            })?;
        let denied = ApprovalEvent {
            version: 1,
            id: request.id.clone(),
            signature: hex(&signature),
            reason: Some(format!("superseded by edited request {replacement_id}")),
            executed: false,
        };
        self.audit(
            id,
            "analyst",
            "ApprovalDenied",
            &serde_json::to_string(&denied).map_err(|e| AppError::Storage(e.to_string()))?,
            None,
        )?;
        self.audit(
            id,
            "analyst",
            "Proposal",
            &format!("{} {:?}", proposal.tool.as_str(), proposal.args),
            None,
        )?;
        Ok(())
    }

    pub(crate) fn resolve_approval_unlocked(
        &self,
        id: &CaseId,
        request_id: &str,
        denial: Option<&str>,
    ) -> Result<Option<AuthorizedCall>, AppError> {
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        let request = self
            .pending_requests_unlocked(&case, &self.audit_log.entries(id)?)?
            .into_iter()
            .find(|request| request.id == request_id)
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyPendingApprovalNotFound,
            ))?;
        if denial.is_none() {
            self.policy
                .permits(&request.tool, self.completed_calls_unlocked(id)?)
                .map_err(|reason| AppError::Policy(reason.into()))?;
            self.audit(
                id,
                "system",
                "PolicyActivated",
                &self.policy_fingerprint,
                None,
            )?;
        }
        let pending = PendingApproval::recover_with_rules(
            &case,
            request.mode,
            &request.challenge,
            self.clock.now()?,
            &self.policy,
        )
        .map_err(|_| {
            AppError::Fixed(crate::FixedAppError::PolicyStoredApprovalChallengeIsInvalid)
        })?;
        let verifier = AnalystVerifierAdapter(self.verifier.as_ref());
        let (kind, signature, reason, authorized) = if let Some(reason) = denial {
            let signature = self.signer.sign(&pending.rejection_challenge())?;
            pending.reject(&signature, &verifier).map_err(|_| {
                AppError::Fixed(crate::FixedAppError::SignatureAnalystDenialSignatureIsInvalid)
            })?;
            ("ApprovalDenied", signature, Some(reason.to_owned()), None)
        } else {
            let signature = self.signer.sign(&pending.challenge())?;
            let authorized = pending
                .resolve(&signature, &verifier, self.clock.now()?)
                .map_err(|_| {
                    AppError::Fixed(
                        crate::FixedAppError::SignatureAnalystApprovalSignatureIsInvalid,
                    )
                })?;
            ("ApprovalGranted", signature, None, Some(authorized))
        };
        let event = ApprovalEvent {
            version: 1,
            id: request.id.clone(),
            signature: hex(&signature),
            reason,
            executed: false,
        };
        self.audit(
            id,
            "analyst",
            kind,
            &serde_json::to_string(&event).map_err(|e| AppError::Storage(e.to_string()))?,
            None,
        )?;
        Ok(authorized)
    }

    pub(crate) async fn resolve_approval(
        &self,
        id: &CaseId,
        request_id: &str,
        denial: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.require_attended_analyst("resolve approval")?;
        let id_owned = id.clone();
        let _case_lock = self
            .blocking_local(move |local| local.repo.lock_case(&id_owned))
            .await?;
        let id_owned = id.clone();
        let request_id = request_id.to_owned();
        let denial = denial.map(str::to_owned);
        let authorized = self
            .blocking_local(move |local| {
                local.resolve_approval_unlocked(&id_owned, &request_id, denial.as_deref())
            })
            .await?;
        if let Some(call) = authorized {
            if let Some(reason) = self.unavailable_reason(&call) {
                self.audit_local(id, "policy", "Denied", reason, None)
                    .await?;
                return Ok(format!("approval recorded; {reason}; no request was sent"));
            }
            let (_, hash) = self.execute_authorized(id, &call, true, cancel).await?;
            Ok(format!("approval executed; evidence {hash}"))
        } else {
            Ok("request denied and recorded".into())
        }
    }

    pub(crate) fn pending_requests_unlocked(
        &self,
        case: &Case,
        entries: &[SignedEntry],
    ) -> Result<Vec<ApprovalRequest>, AppError> {
        let mut open = BTreeMap::<String, ApprovalRequest>::new();
        let verifier = AnalystVerifierAdapter(self.verifier.as_ref());
        for entry in entries {
            if entry.kind == irmind_domain::AuditEventKind::NeedsApproval {
                let request = self.parse_pending_event(case, entry)?;
                if open.insert(request.id.clone(), request).is_some() {
                    return Err(AppError::InvalidChain(entry.seq));
                }
            } else if entry.kind == irmind_domain::AuditEventKind::ApprovalGranted
                || entry.kind == irmind_domain::AuditEventKind::ApprovalDenied
            {
                let event: ApprovalEvent = serde_json::from_str(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                let request = open
                    .remove(&event.id)
                    .ok_or(AppError::InvalidChain(entry.seq))?;
                if event.version != 1
                    || event.executed
                    || entry.actor != Actor::Analyst
                    || (entry.kind == irmind_domain::AuditEventKind::ApprovalGranted
                        && event.reason.is_some())
                    || (entry.kind == irmind_domain::AuditEventKind::ApprovalDenied
                        && event
                            .reason
                            .as_ref()
                            .is_none_or(|reason| reason.trim().is_empty() || reason.len() > 500))
                {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                let mut message = request.challenge;
                if entry.kind == irmind_domain::AuditEventKind::ApprovalDenied {
                    message.extend_from_slice(b"\0deny");
                }
                let signature =
                    hex::decode(&event.signature).map_err(|_| AppError::InvalidChain(entry.seq))?;
                if !verifier.verify_analyst(&message, &signature) {
                    return Err(AppError::InvalidChain(entry.seq));
                }
            }
        }
        Ok(open.into_values().collect())
    }

    pub(crate) fn parse_pending_event(
        &self,
        case: &Case,
        entry: &SignedEntry,
    ) -> Result<ApprovalRequest, AppError> {
        let (id, mode, challenge, structured) = if entry.payload.starts_with('{') {
            let event: PendingEvent = serde_json::from_str(&entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            if event.version != 1 {
                return Err(AppError::InvalidChain(entry.seq));
            }
            let mode = match event.mode.as_str() {
                "attended" => ExecutionMode::Attended,
                "unattended" => ExecutionMode::Unattended,
                _ => return Err(AppError::InvalidChain(entry.seq)),
            };
            let challenge =
                hex::decode(&event.challenge).map_err(|_| AppError::InvalidChain(entry.seq))?;
            (
                event.id,
                mode,
                challenge,
                Some((event.decision_seq, event.tool, event.args)),
            )
        } else {
            let (id, challenge) = entry
                .payload
                .strip_prefix("id=")
                .and_then(|value| value.split_once(";challenge="))
                .ok_or(AppError::InvalidChain(entry.seq))?;
            (
                id.to_owned(),
                ExecutionMode::Attended,
                hex::decode(challenge).map_err(|_| AppError::InvalidChain(entry.seq))?,
                None,
            )
        };
        let pending =
            PendingApproval::recover_with_rules(case, mode, &challenge, entry.at, &self.policy)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
        if pending.decision_seq() != entry.seq
            || id != hex(&sha256(&challenge))
            || structured.as_ref().is_some_and(|(seq, tool, args)| {
                *seq != entry.seq
                    || tool != pending.proposal().tool.as_str()
                    || args != &pending.proposal().args
            })
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        Ok(ApprovalRequest {
            id,
            tool: pending.proposal().tool.clone(),
            args: pending.proposal().args.clone(),
            mode,
            decision_seq: entry.seq,
            challenge,
        })
    }
}
