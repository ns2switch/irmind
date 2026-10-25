use crate::{
    Actor, AppError, CancellationToken, CaseId, CaseMutation, CaseSeal, Engine, hex,
    seal_challenge, sha256, summarize_usage, verify_case_metadata,
};

impl Engine<'_> {
    pub fn seal(&self, id: &CaseId) -> Result<(), AppError> {
        self.require_attended_analyst("seal case")?;
        let _case_lock = self.repo.lock_case(id)?;
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        if !self
            .pending_requests_unlocked(&case, &self.audit_log.entries(id)?)?
            .is_empty()
        {
            return Err(AppError::Policy(
                "resolve pending approvals before sealing".into(),
            ));
        }
        let manifest = self.evidence_store.evidence_hashes(id)?.join(",");
        let entry = self.signed_entry(id, "analyst", "CaseSealed", &manifest, None)?;
        let seal = CaseSeal {
            seq: entry.seq,
            hash: entry.hash,
            sig: self
                .signer
                .sign(&seal_challenge(id, entry.seq, &entry.hash, &manifest))?,
            public_key: self.signer.public_key(),
            analyst_key_fingerprint: hex(&sha256(&self.signer.public_key())),
        };
        self.audit_log
            .transact(&entry, CaseMutation::Seal(id.clone()))?;
        self.repo.write_seal_file(id, &seal)
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
        let case = self.repo.get_case(id)?;
        let entries = self.audit_log.entries(id)?;
        verify_case_metadata(&case.title, case.severity, &case.scope, &entries)?;
        let mut prev = [0u8; 32];
        for (index, entry) in entries.iter().enumerate() {
            if index % 256 == 0 && cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if entry.seq != index as u64 + 1
                || entry.case_id != id.as_str()
                || entry.prev != prev
                || sha256(&entry.canonical()) != entry.hash
            {
                return Err(AppError::InvalidChain(entry.seq));
            }
            if entry.public_key != self.verifier.trusted_public_key(&entry.actor)? {
                return Err(AppError::InvalidChain(entry.seq));
            }
            self.verifier
                .verify(&entry.public_key, &entry.hash, &entry.sig)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            prev = entry.hash;
        }
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
                || last.kind != "CaseSealed"
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
        Ok(entries.len())
    }
}
