use super::{
    AppError, CancellationToken, CaseId, LargeCaseUseCases, Path, SourceCheckMode,
    SourceCheckReport, read_manifest_index, select_sources,
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
        let index = read_manifest_index(&entries)?;

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
        let index = read_manifest_index(&entries)?;

        let checked = if index.sources.is_empty() {
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
        Ok(checked)
    }
}
