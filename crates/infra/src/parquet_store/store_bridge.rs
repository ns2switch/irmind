use super::{
    AppError, CancellationToken, CaseId, LargeCaseStore, ParquetArtifact, Path, SourceManifestV1,
    StreamingEventParser,
};

impl LargeCaseStore for crate::LocalStore {
    fn prepare_source_query_capture(
        &self,
        request: &irmind_app::MappedIngestRequest<'_>,
        capture: &irmind_app::source_queries::SourceQueryResultV1,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn irmind_app::PreparedMappedIngest>, AppError> {
        self.parquet
            .prepare_source_query_capture(request, capture, cancel)
    }

    fn open_source_query_capture(
        &self,
        case: &CaseId,
        hash: &irmind_domain::EvidenceHash,
        bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn std::io::Read + Send>, AppError> {
        self.parquet
            .open_source_query_capture(case, hash, bytes, cancel)
    }

    fn prepare_mapped_ingest(
        &self,
        request: irmind_app::MappedIngestRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<Option<Box<dyn irmind_app::PreparedMappedIngest>>, AppError> {
        self.parquet.prepare_mapped_ingest(request, cancel)
    }

    fn create_object_spool(
        &self,
        case_id: &CaseId,
        expected_bytes: u64,
    ) -> Result<tempfile::NamedTempFile, AppError> {
        self.parquet.create_object_spool(case_id, expected_bytes)
    }

    fn clean_orphan_spools(&self, case_id: &CaseId) -> Result<usize, AppError> {
        use irmind_app::{AuditLog as _, Repository as _};
        use irmind_domain::{AuditEventKind, EvidenceHash};

        // The engine has verified the complete chain with trusted keys while
        // holding the case lock. Check the storage inventory before deleting.
        self.signed_parquet_artifacts(case_id)?;
        let entries = self.entries(case_id)?;
        if self.get_case(case_id)?.sealed
            || entries
                .iter()
                .any(|entry| entry.kind == AuditEventKind::CaseSealed)
        {
            return Ok(0);
        }
        let mut retained = std::collections::BTreeSet::new();
        for entry in &entries {
            if entry.kind == AuditEventKind::SourceQueryResultV1 {
                let result = irmind_app::source_queries::SourceQueryResultV1::decode(
                    entry.payload.as_bytes(),
                )
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
                let hash = EvidenceHash::parse(result.capture_identity().0)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if result.case_id() != case_id.as_str() || !retained.insert(hash) {
                    return Err(AppError::InvalidChain(entry.seq));
                }
            }
        }
        let spools = self.parquet.clean_orphan_spools(case_id)?;
        let captures = self
            .parquet
            .clean_orphan_query_captures(case_id, &retained)?;
        Ok(spools + captures)
    }

    fn compact_artifacts(
        &self,
        case_id: &CaseId,
        sources: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<ParquetArtifact, AppError> {
        self.parquet.compact_artifacts(case_id, sources, cancel)
    }

    fn verify_local_source(
        &self,
        source_root: &Path,
        manifest: &SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.parquet
            .verify_local_source(source_root, manifest, cancel)
    }

    fn verify_copied_source(
        &self,
        case_id: &CaseId,
        manifest: &SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.parquet.verify_copied_source(case_id, manifest, cancel)
    }

    fn verify_artifact(
        &self,
        case_id: &CaseId,
        artifact: &ParquetArtifact,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.parquet.verify_artifact(case_id, artifact, cancel)
    }

    fn rebuild_compare(
        &self,
        case_id: &CaseId,
        source_root: &Path,
        _sources: &[SourceManifestV1],
        _artifacts: &[ParquetArtifact],
        _parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        use irmind_app::AuditLog as _;
        self.parquet
            .rebuild_mapped_history(case_id, source_root, &self.entries(case_id)?, cancel)
    }
}
