use crate::{
    AppError, CancellationToken, CaseId, Engine, SignedEntry, hex, sha256, summarize_usage,
    verify_case_metadata,
};
use std::collections::HashSet;

#[derive(Clone, Copy)]
pub(crate) struct VerifiedCheckpoint {
    pub seq: u64,
    pub hash: [u8; 32],
}

impl Engine<'_> {
    pub(crate) fn clear_verified_checkpoint(&self, id: &CaseId) -> Result<(), AppError> {
        self.verified_cases
            .lock()
            .map_err(|_| AppError::Storage("verification cache unavailable".into()))?
            .remove(id);
        Ok(())
    }

    pub(crate) fn remember_verified_checkpoint(
        &self,
        id: &CaseId,
        last: Option<&SignedEntry>,
    ) -> Result<(), AppError> {
        let last = last.ok_or(AppError::InvalidChain(0))?;
        self.verified_cases
            .lock()
            .map_err(|_| AppError::Storage("verification cache unavailable".into()))?
            .insert(
                id.clone(),
                VerifiedCheckpoint {
                    seq: last.seq,
                    hash: last.hash,
                },
            );
        Ok(())
    }

    pub(crate) fn verify_ingest_checkpoint(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let checkpoint = self
            .verified_cases
            .lock()
            .map_err(|_| AppError::Storage("verification cache unavailable".into()))?
            .get(id)
            .copied();
        let Some(checkpoint) = checkpoint else {
            self.verify_unlocked_cancelable(id, cancel)?;
            return Ok(());
        };
        let result = self.verify_since_checkpoint(id, checkpoint, cancel);
        if result.is_err() {
            self.clear_verified_checkpoint(id)?;
        }
        result
    }

    fn verify_since_checkpoint(
        &self,
        id: &CaseId,
        checkpoint: VerifiedCheckpoint,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let case = self.repo.get_case(id)?;
        let entries = self.audit_log.entries(id)?;
        let offset = usize::try_from(checkpoint.seq).map_err(|_| AppError::InvalidChain(0))?;
        if offset == 0
            || entries
                .get(offset - 1)
                .is_none_or(|entry| entry.hash != checkpoint.hash)
        {
            return Err(AppError::InvalidChain(checkpoint.seq));
        }
        verify_case_metadata(&case.title, case.severity, &case.scope, &entries)?;
        let mut previous = checkpoint.hash;
        let mut new_evidence = HashSet::new();
        for (index, entry) in entries.iter().enumerate().skip(offset) {
            if index.is_multiple_of(256) && cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            previous = self.verify_chain_entry(id, index, previous, entry)?;
            if let Some(hash) = &entry.evidence {
                new_evidence.insert(hash.clone());
            }
        }
        self.verify_new_evidence(id, &new_evidence, cancel)?;
        crate::large_case::read_manifest_index(&entries)?;
        self.pending_requests_unlocked(&case, &entries)?;
        self.findings_unlocked(id, &entries)?;
        summarize_usage(&entries)?;
        self.verify_operations_unlocked(id, cancel)?;
        self.remember_verified_checkpoint(id, entries.last())
    }

    fn verify_new_evidence(
        &self,
        id: &CaseId,
        hashes: &HashSet<String>,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if hashes.is_empty() {
            return Ok(());
        }
        let listed: HashSet<String> = self
            .evidence_store
            .evidence_hashes(id)?
            .into_iter()
            .collect();
        for hash in hashes {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if !listed.contains(hash)
                || hex(&sha256(&self.evidence_store.get_evidence(id, hash)?)) != *hash
            {
                return Err(AppError::EvidenceMismatch(hash.clone()));
            }
        }
        Ok(())
    }

    pub(crate) fn verify_chain_entry(
        &self,
        id: &CaseId,
        index: usize,
        previous: [u8; 32],
        entry: &SignedEntry,
    ) -> Result<[u8; 32], AppError> {
        if entry.seq != index as u64 + 1
            || entry.case_id != id.as_str()
            || entry.prev != previous
            || sha256(&entry.canonical()) != entry.hash
            || entry.public_key != self.verifier.trusted_public_key(&entry.actor)?
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        self.verifier
            .verify(&entry.public_key, &entry.hash, &entry.sig)
            .map_err(|_| AppError::InvalidChain(entry.seq))?;
        Ok(entry.hash)
    }
}
