use crate::*;

#[derive(Clone)]
pub struct ApprovalRequest {
    pub id: String,
    pub tool: Tool,
    pub args: BTreeMap<String, String>,
    pub mode: ExecutionMode,
    pub decision_seq: u64,
    pub(crate) challenge: Vec<u8>,
}

impl std::fmt::Debug for ApprovalRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalRequest")
            .field("id", &self.id)
            .field("tool", &self.tool)
            .field("decision_seq", &self.decision_seq)
            .field("argument_count", &self.args.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct PendingEvent {
    version: u8,
    id: String,
    mode: String,
    decision_seq: u64,
    tool: String,
    args: BTreeMap<String, String>,
    challenge: String,
}

#[derive(Serialize, Deserialize)]
struct ApprovalEvent {
    version: u8,
    id: String,
    signature: String,
    reason: Option<String>,
    executed: bool,
}

struct AnalystVerifierAdapter<'a>(&'a dyn Verifier);

impl AnalystApprovalVerifier for AnalystVerifierAdapter<'_> {
    fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool {
        self.0
            .trusted_public_key(&Actor::Analyst)
            .is_ok_and(|key| self.0.verify(&key, message, signature).is_ok())
    }
}

struct AuditedDeclassification<'a, 'b> {
    engine: &'a Engine<'b>,
    case_id: &'a CaseId,
}

impl DeclassificationAuthority for AuditedDeclassification<'_, '_> {
    fn verify_and_audit(
        &self,
        challenge: &[u8],
        signature: &[u8],
        provenance: &Provenance,
    ) -> bool {
        let Ok(key) = self.engine.verifier.trusted_public_key(&Actor::Analyst) else {
            return false;
        };
        if self
            .engine
            .verifier
            .verify(&key, challenge, signature)
            .is_err()
        {
            return false;
        }
        let payload = format!(
            "hash={};record={:?};kind={:?};analyst_signature={}",
            hex(provenance.evidence_hash()),
            provenance.record_index(),
            provenance.source_kind(),
            hex(signature),
        );
        self.engine
            .audit(self.case_id, "analyst", "TaintDeclassified", &payload, None)
            .is_ok()
    }
}

impl Engine<'_> {
    pub fn release_tainted<T>(
        &self,
        id: &CaseId,
        value: Tainted<T>,
        analyst_signature: &[u8],
    ) -> Result<T, AppError> {
        self.require_attended_analyst("declassify external value")?;
        let _case_lock = self.repo.lock_case(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        value
            .release_with_approval(
                id,
                analyst_signature,
                &AuditedDeclassification {
                    engine: self,
                    case_id: id,
                },
            )
            .map_err(|_| AppError::Signature("analyst declassification approval required".into()))
    }

    pub(crate) fn audit_pending(
        &self,
        id: &CaseId,
        pending: &PendingApproval,
        mode: ExecutionMode,
    ) -> Result<String, AppError> {
        let challenge = pending.challenge();
        let challenge_id = hex(&sha256(&challenge));
        let event = PendingEvent {
            version: 1,
            id: challenge_id.clone(),
            mode: match mode {
                ExecutionMode::Attended => "attended",
                ExecutionMode::Unattended => "unattended",
            }
            .into(),
            decision_seq: pending.decision_seq(),
            tool: pending.proposal().tool.as_str().into(),
            args: pending.proposal().args.clone(),
            challenge: hex(&challenge),
        };
        self.audit(
            id,
            "policy",
            "NeedsApproval",
            &serde_json::to_string(&event).map_err(|e| AppError::Storage(e.to_string()))?,
            None,
        )?;
        Ok(challenge_id)
    }

    pub fn pending_approvals(&self, id: &CaseId) -> Result<Vec<ApprovalRequest>, AppError> {
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        let case = self.repo.get_case(id)?;
        self.pending_requests_unlocked(&case, &self.audit_log.entries(id)?)
    }

    pub fn approve(&self, id: &CaseId, request_id: &str) -> Result<String, AppError> {
        self.approve_with_cancel(id, request_id, &CancellationToken::new())
    }

    pub fn approve_with_cancel(
        &self,
        id: &CaseId,
        request_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        run_async(self.resolve_approval(id, request_id, None, cancel))
    }

    pub fn deny(&self, id: &CaseId, request_id: &str, reason: &str) -> Result<String, AppError> {
        if reason.trim().is_empty() || reason.len() > 500 {
            return Err(AppError::Policy(
                "denial reason must be 1..500 bytes".into(),
            ));
        }
        run_async(self.resolve_approval(id, request_id, Some(reason), &CancellationToken::new()))
    }

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
            .ok_or_else(|| AppError::Policy("pending approval not found".into()))?;
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
        let decision_seq = last
            .seq
            .checked_add(3)
            .ok_or_else(|| AppError::Storage("audit sequence overflow".into()))?;
        let Decision::NeedsApproval(replacement) = evaluate(
            &case,
            proposal.clone(),
            decision_seq,
            request.mode,
            self.clock.now()?,
        ) else {
            return Err(AppError::Policy(
                "edited arguments do not produce a pending approval".into(),
            ));
        };
        let replacement_id = hex(&sha256(&replacement.challenge()));
        let old =
            PendingApproval::recover(&case, request.mode, &request.challenge, self.clock.now()?)
                .map_err(|_| AppError::Policy("stored approval challenge is invalid".into()))?;
        let signature = self.signer.sign(&old.rejection_challenge())?;
        old.reject(&signature, &AnalystVerifierAdapter(self.verifier.as_ref()))
            .map_err(|_| AppError::Signature("analyst denial signature is invalid".into()))?;
        let denied = ApprovalEvent {
            version: 1,
            id: request.id,
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
        let stored_id = self.audit_pending(id, &replacement, request.mode)?;
        if stored_id != replacement_id {
            return Err(AppError::Policy("edited request id mismatch".into()));
        }
        Ok(format!(
            "edited request pending: {replacement_id}; no tool was executed"
        ))
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
            .ok_or_else(|| AppError::Policy("pending approval not found".into()))?;
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
        let pending =
            PendingApproval::recover(&case, request.mode, &request.challenge, self.clock.now()?)
                .map_err(|_| AppError::Policy("stored approval challenge is invalid".into()))?;
        let verifier = AnalystVerifierAdapter(self.verifier.as_ref());
        let (kind, signature, reason, authorized) = if let Some(reason) = denial {
            let signature = self.signer.sign(&pending.rejection_challenge())?;
            pending
                .reject(&signature, &verifier)
                .map_err(|_| AppError::Signature("analyst denial signature is invalid".into()))?;
            ("ApprovalDenied", signature, Some(reason.to_owned()), None)
        } else {
            let signature = self.signer.sign(&pending.challenge())?;
            let authorized = pending
                .resolve(&signature, &verifier, self.clock.now()?)
                .map_err(|_| AppError::Signature("analyst approval signature is invalid".into()))?;
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
            if entry.kind == "NeedsApproval" {
                let request = Self::parse_pending_event(case, entry)?;
                if open.insert(request.id.clone(), request).is_some() {
                    return Err(AppError::InvalidChain(entry.seq));
                }
            } else if entry.kind == "ApprovalGranted" || entry.kind == "ApprovalDenied" {
                let event: ApprovalEvent = serde_json::from_str(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                let request = open
                    .remove(&event.id)
                    .ok_or(AppError::InvalidChain(entry.seq))?;
                if event.version != 1
                    || event.executed
                    || entry.actor != Actor::Analyst
                    || (entry.kind == "ApprovalGranted" && event.reason.is_some())
                    || (entry.kind == "ApprovalDenied"
                        && event
                            .reason
                            .as_ref()
                            .is_none_or(|reason| reason.trim().is_empty() || reason.len() > 500))
                {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                let mut message = request.challenge;
                if entry.kind == "ApprovalDenied" {
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
        let pending = PendingApproval::recover(case, mode, &challenge, entry.at)
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
