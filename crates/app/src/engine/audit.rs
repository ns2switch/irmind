use super::Engine;
use crate::{
    Actor, AppError, AuditEventKind, AuditOrigin, CaseId, ExecutionMode, SignedEntry, sha256,
};

impl Engine<'_> {
    /// Record why unattended ingestion stopped without storing attacker-controlled
    /// source names in the signed operational description.
    pub fn record_parser_selection_required(
        &self,
        id: &CaseId,
        reason: &'static str,
    ) -> Result<(), AppError> {
        if !matches!(
            reason,
            "ambiguous" | "low-confidence" | "unsupported" | "missing-time-context"
        ) {
            return Err(AppError::Policy("invalid parser refusal reason".into()));
        }
        self.audit(
            id,
            AuditOrigin::System,
            AuditEventKind::ParserSelectionRequired,
            reason,
            None,
        )
    }

    pub(crate) fn audit(
        &self,
        id: &CaseId,
        origin: AuditOrigin,
        kind: AuditEventKind,
        payload: &str,
        evidence: Option<&str>,
    ) -> Result<(), AppError> {
        let entry = self.signed_entry(id, origin, kind, payload, evidence)?;
        self.audit_log.append(&entry)
    }

    pub(crate) fn audit_model_text(
        &self,
        id: &CaseId,
        kind: AuditEventKind,
        text: &str,
    ) -> Result<String, AppError> {
        let mut entry = self.signed_entry(id, AuditOrigin::Model, kind, text, None)?;
        let visible = crate::ports::model::output::fit_frame(text, |candidate| {
            candidate.clone_into(&mut entry.payload);
            // Fixed-width signatures and bounded metadata; hash is recomputed below.
            serde_json::to_vec(&entry)
                .map(|bytes| bytes.len())
                .map_err(|e| AppError::Storage(e.to_string()))
        })?;
        // Audit hashes and signatures cover the retained text, including its notice.
        let mut entry = self.signed_entry(id, AuditOrigin::Model, kind, &visible, None)?;
        // Hash byte arrays can change JSON width after signing. Recheck the final
        // representation and trim only the explicit security-limit edge case.
        while serde_json::to_vec(&entry)
            .map_err(|e| AppError::Storage(e.to_string()))?
            .len()
            > crate::ports::model::output::FRAME_BYTES
        {
            let shortened = crate::ports::model::output::utf8_prefix(
                &entry.payload,
                entry.payload.len().saturating_sub(256),
            );
            let text = format!(
                "{shortened}\n\n{}",
                crate::ports::model::output::SECURITY_NOTICE
            );
            entry = self.signed_entry(id, AuditOrigin::Model, kind, &text, None)?;
        }
        let visible = entry.payload.clone();
        self.audit_log.append(&entry)?;
        Ok(visible)
    }

    pub(crate) fn audit_batch(
        &self,
        id: &CaseId,
        events: &[(AuditOrigin, AuditEventKind, String)],
    ) -> Result<(), AppError> {
        let signed = self.prepare_audit_batch(id, events)?;
        self.audit_log.append_batch(&signed)
    }

    pub(crate) fn prepare_audit_batch(
        &self,
        id: &CaseId,
        events: &[(AuditOrigin, AuditEventKind, String)],
    ) -> Result<Vec<SignedEntry>, AppError> {
        if events.is_empty() {
            return Err(AppError::InvalidChain(0));
        }
        let last = self.audit_log.last_entry(id)?;
        let mut signed = Vec::with_capacity(events.len());
        for (origin, kind, payload) in events {
            let previous = signed.last().or(last.as_ref());
            signed.push(self.signed_entry_after(id, previous, *origin, *kind, payload, None)?);
        }
        Ok(signed)
    }

    pub(crate) fn signed_entry(
        &self,
        id: &CaseId,
        origin: AuditOrigin,
        kind: AuditEventKind,
        payload: &str,
        evidence: Option<&str>,
    ) -> Result<SignedEntry, AppError> {
        let last = self.audit_log.last_entry(id)?;
        self.signed_entry_after(id, last.as_ref(), origin, kind, payload, evidence)
    }

    pub(crate) fn signed_entry_after(
        &self,
        id: &CaseId,
        last: Option<&SignedEntry>,
        origin: AuditOrigin,
        kind: AuditEventKind,
        payload: &str,
        evidence: Option<&str>,
    ) -> Result<SignedEntry, AppError> {
        let at = self.clock.now()?;
        let mut entry = SignedEntry {
            seq: last.map_or(Ok(1), |entry| {
                entry.seq.checked_add(1).ok_or(AppError::Fixed(
                    crate::FixedAppError::PolicyAuditSequenceExhausted,
                ))
            })?,
            case_id: id.as_str().to_owned(),
            at,
            actor: self.signer.actor(),
            origin: origin.as_str().to_owned(),
            kind,
            payload: payload.to_owned(),
            evidence: evidence.map(str::to_owned),
            prev: last.map_or([0; 32], |entry| entry.hash),
            hash: [0; 32],
            sig: Vec::new(),
            public_key: self.signer.public_key(),
        };
        entry.hash = sha256(&entry.canonical());
        entry.sig = self.signer.sign(&entry.hash)?;
        Ok(entry)
    }

    pub(crate) fn require_attended_analyst(&self, operation: &str) -> Result<(), AppError> {
        if self.mode == ExecutionMode::Attended && self.signer.actor() == Actor::Analyst {
            Ok(())
        } else {
            Err(AppError::PendingApproval(operation.to_owned()))
        }
    }
}
