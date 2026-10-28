use super::{
    AppError, AuditEventKind, AuditOrigin, BTreeMap, BTreeSet, CancellationToken, CaseId,
    LargeCaseUseCases, ParquetArtifactV1, invalid_manifest, read_manifest_index,
};

impl LargeCaseUseCases<'_, '_> {
    pub fn migrate_legacy(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        if self.engine.repo.get_case(id)?.sealed {
            self.migrate_legacy_sealed(id, cancel)
        } else {
            self.migrate_legacy_open(id, cancel)
        }
    }

    /// Convert legacy copied JSON evidence in an open case without changing
    /// its original signed entries. Only new derived artifacts are appended.
    pub fn migrate_legacy_open(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.engine
            .require_attended_analyst("migrate legacy evidence")?;
        let _case_lock = self.engine.repo.lock_case(id)?;
        if self.engine.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.engine.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.engine.audit_log.entries(id)?;
        let mut existing = read_manifest_index(&entries)?
            .artifacts
            .into_iter()
            .map(|artifact| (artifact.path.clone(), artifact))
            .collect::<BTreeMap<_, _>>();
        let hashes = entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::GraphIndexed)
            .filter_map(|entry| entry.evidence.as_deref())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let mut converted = 0usize;
        for hash in hashes {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let bytes = self.engine.evidence_store.get_evidence(id, &hash)?;
            let artifacts =
                self.store
                    .prepare_legacy_evidence(id, &hash, &bytes, self.parser, cancel)?;
            let mut added = false;
            for artifact in artifacts {
                self.store.verify_artifact(id, &artifact, cancel)?;
                added |= !existing.contains_key(&artifact.path);
                self.audit_artifact(id, artifact, &mut existing)?;
            }
            if added {
                converted += 1;
            }
        }
        self.engine.verify_unlocked_cancelable(id, cancel)?;
        Ok(converted)
    }

    /// Preserve the sealed case chain and record derived artifacts in the
    /// separately signed operational chain, bound to the existing seal hash.
    pub fn migrate_legacy_sealed(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.engine
            .require_attended_analyst("migrate sealed legacy evidence")?;
        let _case_lock = self.engine.repo.lock_case(id)?;
        if !self.engine.repo.get_case(id)?.sealed {
            return Err(AppError::Policy("case is not sealed".into()));
        }
        self.engine.verify_unlocked_cancelable(id, cancel)?;
        let seal = self
            .engine
            .repo
            .case_seal(id)?
            .ok_or(AppError::InvalidChain(0))?;
        let entries = self.engine.audit_log.entries(id)?;
        let operations = self.engine.audit_log.operations(id)?;
        let mut existing = super::read_sealed_artifacts(&entries, &operations, seal.hash)?
            .into_iter()
            .map(|artifact| (artifact.path.clone(), artifact))
            .collect::<BTreeMap<_, _>>();
        let hashes = entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::GraphIndexed)
            .filter_map(|entry| entry.evidence.as_deref())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let mut converted = 0;
        for hash in hashes {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let bytes = self.engine.evidence_store.get_evidence(id, &hash)?;
            let mut added = false;
            for artifact in
                self.store
                    .prepare_legacy_evidence(id, &hash, &bytes, self.parser, cancel)?
            {
                self.store.verify_artifact(id, &artifact, cancel)?;
                if let Some(previous) = existing.get(&artifact.path) {
                    if previous != &artifact {
                        return Err(AppError::EvidenceMismatch(artifact.path));
                    }
                    continue;
                }
                let record = irmind_domain::SealedParquetMigrationV1 {
                    seal_hash: seal.hash,
                    artifact: artifact.clone(),
                };
                self.engine.record_operational_event_unlocked(
                    id,
                    &record.encode().map_err(|_| invalid_manifest())?,
                )?;
                existing.insert(artifact.path.clone(), artifact);
                added = true;
            }
            if added {
                converted += 1;
            }
        }
        self.engine.verify_unlocked_cancelable(id, cancel)?;
        Ok(converted)
    }

    pub(super) fn audit_artifact(
        &self,
        id: &CaseId,
        artifact: ParquetArtifactV1,
        existing: &mut BTreeMap<String, ParquetArtifactV1>,
    ) -> Result<(), AppError> {
        if let Some(previous) = existing.get(&artifact.path) {
            if previous != &artifact {
                return Err(AppError::EvidenceMismatch(artifact.path));
            }
            return Ok(());
        }
        self.engine.audit(
            id,
            AuditOrigin::System,
            AuditEventKind::ParquetArtifactV1,
            &artifact.encode().map_err(|_| invalid_manifest())?,
            None,
        )?;
        existing.insert(artifact.path.clone(), artifact);
        Ok(())
    }
}
