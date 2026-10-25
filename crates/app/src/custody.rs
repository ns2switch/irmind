use crate::{
    Actor, AppError, CancellationToken, CancelledOperation, CaseId, CaseMutation, CaseSeal, Engine,
    SignedEntry, SignedOperation, hex, seal_challenge, sha256, summarize_usage,
    verify_case_metadata,
};
use std::path::Path;

pub fn verify_export(
    verifier: &dyn crate::ExportVerifier,
    path: &Path,
    expected_key: Option<&str>,
) -> Result<(String, usize), AppError> {
    verifier.verify_export(path, expected_key)
}

pub fn export_case(
    engine: &Engine<'_>,
    exporter: &dyn crate::CaseExporter,
    id: &CaseId,
    path: &Path,
    cancel: &CancellationToken,
) -> Result<String, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let _case_lock = engine.repo.lock_case(id)?;
    engine.verify_unlocked_cancelable(id, cancel)?;
    if !engine.repo.get_case(id)?.sealed {
        return Err(AppError::Policy("seal the case before export".into()));
    }
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    exporter.export_case(id, path, cancel)
}

pub struct SealPreview {
    entry: SignedEntry,
    seal: CaseSeal,
}

impl SealPreview {
    pub fn case_id(&self) -> &str {
        &self.entry.case_id
    }
    pub fn entry_count(&self) -> u64 {
        self.entry.seq
    }
    pub fn final_hash(&self) -> [u8; 32] {
        self.entry.hash
    }
    pub fn analyst_key_fingerprint(&self) -> &str {
        &self.seal.analyst_key_fingerprint
    }
}

impl Engine<'_> {
    pub fn record_cancellation(
        &self,
        id: &CaseId,
        operation: CancelledOperation,
    ) -> Result<(), AppError> {
        let _case_lock = self.repo.lock_case(id)?;
        self.repo.get_case(id)?;
        self.verify_operations_unlocked(id, &CancellationToken::new())?;
        let last = self.audit_log.last_operation(id)?;
        let mut entry = SignedOperation {
            case_id: id.as_str().into(),
            seq: last.as_ref().map_or(Ok(1), |previous| {
                previous
                    .seq
                    .checked_add(1)
                    .ok_or_else(|| AppError::Policy("operational audit sequence exhausted".into()))
            })?,
            at: self.clock.now()?,
            actor: self.signer.actor(),
            operation: operation.as_str().into(),
            prev: last.map_or([0u8; 32], |previous| previous.hash),
            hash: [0u8; 32],
            sig: Vec::new(),
            public_key: self.signer.public_key(),
        };
        entry.hash = sha256(&entry.canonical());
        entry.sig = self.signer.sign(&entry.hash)?;
        self.audit_log.append_operation(&entry)
    }

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
            return Err(AppError::Policy(
                "resolve pending approvals before sealing".into(),
            ));
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
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
            return Err(AppError::Policy("seal preview is stale".into()));
        }
        if !self
            .pending_requests_unlocked(&self.repo.get_case(&id)?, &self.audit_log.entries(&id)?)?
            .is_empty()
        {
            return Err(AppError::Policy(
                "resolve pending approvals before sealing".into(),
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
        self.verify_operations_unlocked(id, cancel)?;
        Ok(entries.len())
    }

    fn verify_operations_unlocked(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let operations = self.audit_log.operations(id)?;
        let mut previous = [0u8; 32];
        for (index, operation) in operations.iter().enumerate() {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if operation.case_id != id.as_str()
                || operation.seq != index as u64 + 1
                || operation.prev != previous
                || sha256(&operation.canonical()) != operation.hash
                || operation.public_key != self.verifier.trusted_public_key(&operation.actor)?
            {
                return Err(AppError::InvalidChain(operation.seq));
            }
            self.verifier
                .verify(&operation.public_key, &operation.hash, &operation.sig)
                .map_err(|_| AppError::InvalidChain(operation.seq))?;
            previous = operation.hash;
        }
        Ok(())
    }
}
