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
            .map_err(|_| {
                AppError::Fixed(
                    crate::FixedAppError::SignatureAnalystDeclassificationApprovalRequired,
                )
            })
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
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDenialReasonMustBe1500Bytes,
            ));
        }
        run_async(self.resolve_approval(id, request_id, Some(reason), &CancellationToken::new()))
    }
}
