use super::{
    AppError, AuditEventKind, AuditOrigin, CancellationToken, CaseId, LargeCaseUseCases, Path,
    invalid_manifest,
};

impl LargeCaseUseCases<'_, '_> {
    pub fn migrate_artifacts_v2(
        &self,
        id: &CaseId,
        source_root: Option<&Path>,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.engine
            .require_attended_analyst("migrate Parquet artifacts")?;
        let _lock = self.engine.repo.lock_case(id)?;
        if self.engine.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.engine.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.engine.audit_log.entries(id)?;
        let mut prepared = self.store.prepare_artifact_migration(
            crate::ArtifactMigrationRequest {
                case_id: id,
                source_root,
                signed_entries: &entries,
                parser: self.parser,
                limits: crate::PartitionLimits::default(),
            },
            cancel,
        )?;
        let mut events = Vec::new();
        for artifact in prepared.artifacts() {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            events.push((
                AuditOrigin::System,
                AuditEventKind::ParquetArtifactV2,
                artifact.encode().map_err(|_| invalid_manifest())?,
            ));
        }
        let count = prepared.artifacts().len();
        events.push((
            AuditOrigin::Analyst,
            AuditEventKind::ParquetArtifactsMigrated,
            prepared.record().encode().map_err(|_| invalid_manifest())?,
        ));
        let signed = self.engine.prepare_audit_batch(id, &events)?;
        let mut combined = entries;
        combined.extend(signed.iter().cloned());
        crate::artifact_catalog(&combined)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        prepared.publish(cancel)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.engine.audit_log.append_batch(&signed)?;
        prepared.retain_committed();
        let committed = CancellationToken::new();
        self.engine.verify_unlocked_cancelable(id, &committed)?;
        for artifact in prepared.artifacts() {
            self.store
                .verify_artifact(id, &artifact.clone().into(), &committed)?;
        }
        Ok(count)
    }
}
