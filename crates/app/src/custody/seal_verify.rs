use super::SealPreview;
use crate::{
    Actor, AppError, CancellationToken, CaseId, CaseMutation, CaseSeal, Engine, hex,
    seal_challenge, sha256, summarize_usage, verify_case_metadata,
};

impl Engine<'_> {
    pub fn seal(&self, id: &CaseId) -> Result<(), AppError> {
        let preview = self.prepare_seal(id)?;
        self.seal_prepared(&preview)
    }

    pub fn prepare_seal(&self, id: &CaseId) -> Result<SealPreview, AppError> {
        self.prepare_seal_cancelable(id, &CancellationToken::new())
    }

    pub fn prepare_seal_cancelable(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<SealPreview, AppError> {
        self.require_attended_analyst("seal case")?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let _case_lock = self.repo.lock_case(id)?;
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked_cancelable(id, cancel)?;
        if !self
            .pending_requests_unlocked(&case, &self.audit_log.entries(id)?)?
            .is_empty()
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyResolvePendingApprovalsBeforeSealing,
            ));
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let manifest = self.evidence_store.evidence_hashes(id)?.join(",");
        let entry = self.signed_entry(
            id,
            crate::AuditOrigin::Analyst,
            irmind_domain::AuditEventKind::CaseSealed,
            &manifest,
            None,
        )?;
        let seal = CaseSeal {
            seq: entry.seq,
            hash: entry.hash,
            sig: self
                .signer
                .sign(&seal_challenge(id, entry.seq, &entry.hash, &manifest))?,
            public_key: self.signer.public_key(),
            analyst_key_fingerprint: hex(&sha256(&self.signer.public_key())),
        };
        Ok(SealPreview { entry, seal })
    }

    pub fn seal_prepared(&self, preview: &SealPreview) -> Result<(), AppError> {
        self.require_attended_analyst("seal case")?;
        let id = CaseId::parse(&preview.entry.case_id).map_err(|_| AppError::InvalidCaseId)?;
        let _case_lock = self.repo.lock_case(&id)?;
        if self.repo.get_case(&id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(&id)?;
        let last = self
            .audit_log
            .last_entry(&id)?
            .ok_or(AppError::InvalidChain(0))?;
        let manifest = self.evidence_store.evidence_hashes(&id)?.join(",");
        if Some(preview.entry.seq) != last.seq.checked_add(1)
            || preview.entry.prev != last.hash
            || preview.entry.payload != manifest
            || preview.entry.actor != Actor::Analyst
            || preview.entry.public_key != self.signer.public_key()
            || sha256(&preview.entry.canonical()) != preview.entry.hash
            || preview.seal.hash != preview.entry.hash
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicySealPreviewIsStale,
            ));
        }
        if !self
            .pending_requests_unlocked(&self.repo.get_case(&id)?, &self.audit_log.entries(&id)?)?
            .is_empty()
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyResolvePendingApprovalsBeforeSealing,
            ));
        }
        self.audit_log
            .transact(&preview.entry, CaseMutation::Seal(id.clone()))?;
        self.repo.write_seal_file(&id, &preview.seal)
    }

    pub fn verify(&self, id: &CaseId) -> Result<usize, AppError> {
        self.verify_cancelable(id, &CancellationToken::new())
    }

    pub fn verify_cancelable(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked_cancelable(id, cancel)
    }

    pub(crate) fn verify_unlocked(&self, id: &CaseId) -> Result<usize, AppError> {
        self.verify_unlocked_cancelable(id, &CancellationToken::new())
    }

    pub(crate) fn verify_unlocked_cancelable(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.clear_verified_checkpoint(id)?;
        let case = self.repo.get_case(id)?;
        let entries = self.audit_log.entries(id)?;
        verify_case_metadata(&case.title, case.severity, &case.scope, &entries)?;
        let mut prev = [0u8; 32];
        for (index, entry) in entries.iter().enumerate() {
            if index % 256 == 0 && cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            prev = self.verify_chain_entry(id, index, prev, entry)?;
        }
        crate::large_case::read_manifest_index(&entries)?;
        let evidence_hashes = self.evidence_store.evidence_hashes(id)?;
        for entry in &entries {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if let Some(hash) = &entry.evidence
                && !evidence_hashes.contains(hash)
            {
                return Err(AppError::EvidenceMismatch(hash.clone()));
            }
        }
        for hash in evidence_hashes {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let bytes = self.evidence_store.get_evidence(id, &hash)?;
            if hex(&sha256(&bytes)) != hash {
                return Err(AppError::EvidenceMismatch(hash));
            }
        }
        if case.sealed {
            let seal = self.repo.case_seal(id)?.ok_or(AppError::InvalidChain(0))?;
            let last = entries.last().ok_or(AppError::InvalidChain(0))?;
            if seal.seq != last.seq
                || seal.hash != last.hash
                || seal.public_key != last.public_key
                || (!seal.analyst_key_fingerprint.is_empty()
                    && seal.analyst_key_fingerprint != hex(&sha256(&last.public_key)))
                || last.kind != irmind_domain::AuditEventKind::CaseSealed
                || last.actor != Actor::Analyst
                || last.payload != self.evidence_store.evidence_hashes(id)?.join(",")
            {
                return Err(AppError::InvalidChain(last.seq));
            }
            self.verifier
                .verify(
                    &seal.public_key,
                    &seal_challenge(id, seal.seq, &seal.hash, &last.payload),
                    &seal.sig,
                )
                .map_err(|_| AppError::InvalidChain(last.seq))?;
        }
        self.pending_requests_unlocked(&case, &entries)?;
        self.findings_unlocked(id, &entries)?;
        summarize_usage(&entries)?;
        self.verify_operations_unlocked(id, cancel)?;
        if case.sealed {
            let seal = self.repo.case_seal(id)?.ok_or(AppError::InvalidChain(0))?;
            crate::large_case::read_sealed_artifacts(
                &entries,
                &self.audit_log.operations(id)?,
                seal.hash,
            )?;
        }
        self.remember_verified_checkpoint(id, entries.last())?;
        Ok(entries.len())
    }
}
