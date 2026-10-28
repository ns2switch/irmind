use super::{
    AppError, AuditEventKind, BTreeSet, CancellationToken, CaseId, LargeCaseUseCases, Path,
    SourceCheckMode, SourceCheckReport, read_manifest_index, read_sealed_artifacts, select_sources,
};

impl LargeCaseUseCases<'_, '_> {
    pub fn verify_sources(
        &self,
        id: &CaseId,
        source_root: &Path,
        mode: SourceCheckMode,
        cancel: &CancellationToken,
    ) -> Result<SourceCheckReport, AppError> {
        let _case_lock = self.engine.repo.lock_case(id)?;
        self.engine.verify_unlocked_cancelable(id, cancel)?;
        let index = read_manifest_index(&self.engine.audit_log.entries(id)?)?;
        let total = index.sources.len();
        let selected = select_sources(index.sources, mode)?;
        let checked = selected.len();
        let mut missing_or_changed = Vec::new();
        for source in selected {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let original = self.store.verify_local_source(source_root, &source, cancel);
            if matches!(original, Err(AppError::Cancelled)) {
                return Err(AppError::Cancelled);
            }
            let copy = if source.copied {
                self.store.verify_copied_source(id, &source, cancel)
            } else {
                Ok(())
            };
            if matches!(copy, Err(AppError::Cancelled)) {
                return Err(AppError::Cancelled);
            }
            if original.is_err() || copy.is_err() {
                missing_or_changed.push(source.sha256.as_str().to_owned());
            }
        }
        Ok(SourceCheckReport {
            total,
            checked,
            missing_or_changed,
            unchecked: total - checked,
        })
    }

    pub fn verify_parquet(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let _case_lock = self.engine.repo.lock_case(id)?;
        self.engine.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.engine.audit_log.entries(id)?;
        let mut index = read_manifest_index(&entries)?;
        if self.engine.repo.get_case(id)?.sealed {
            let seal = self
                .engine
                .repo
                .case_seal(id)?
                .ok_or(AppError::InvalidChain(0))?;
            index.artifacts.extend(read_sealed_artifacts(
                &entries,
                &self.engine.audit_log.operations(id)?,
                seal.hash,
            )?);
        }
        for artifact in &index.artifacts {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            self.store.verify_artifact(id, artifact, cancel)?;
        }
        Ok(index.artifacts.len())
    }

    pub fn verify_parquet_rebuild(
        &self,
        id: &CaseId,
        source_root: &Path,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let _case_lock = self.engine.repo.lock_case(id)?;
        self.engine.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.engine.audit_log.entries(id)?;
        let mut index = read_manifest_index(&entries)?;
        if self.engine.repo.get_case(id)?.sealed {
            let seal = self
                .engine
                .repo
                .case_seal(id)?
                .ok_or(AppError::InvalidChain(0))?;
            index.artifacts.extend(read_sealed_artifacts(
                &entries,
                &self.engine.audit_log.operations(id)?,
                seal.hash,
            )?);
        }
        let mut checked = if index.sources.is_empty() {
            0
        } else {
            self.store.rebuild_compare(
                id,
                source_root,
                &index.sources,
                &index.artifacts,
                self.parser,
                cancel,
            )?
        };
        let new_hashes = index
            .sources
            .iter()
            .map(|source| source.sha256.as_str())
            .collect::<BTreeSet<_>>();
        let legacy_hashes = entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::GraphIndexed)
            .filter_map(|entry| entry.evidence.as_deref())
            .filter(|hash| !new_hashes.contains(hash))
            .collect::<BTreeSet<_>>();
        for hash in legacy_hashes {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let bytes = self.engine.evidence_store.get_evidence(id, hash)?;
            let mut rebuilt =
                self.store
                    .prepare_legacy_evidence(id, hash, &bytes, self.parser, cancel)?;
            let mut signed = index
                .artifacts
                .iter()
                .filter(|artifact| {
                    artifact.source_hashes.len() == 1 && artifact.source_hashes[0].as_str() == hash
                })
                .cloned()
                .collect::<Vec<_>>();
            rebuilt.sort_by(|left, right| left.path.cmp(&right.path));
            signed.sort_by(|left, right| left.path.cmp(&right.path));
            if rebuilt != signed || rebuilt.is_empty() {
                return Err(AppError::EvidenceMismatch(hash.to_owned()));
            }
            checked += 1;
        }
        Ok(checked)
    }
}
