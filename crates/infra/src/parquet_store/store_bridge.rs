use super::{
    AppError, CancellationToken, CaseId, LargeCaseStore, ParquetArtifact, Path, SourceManifestV1,
    StreamingEventParser,
};

impl LargeCaseStore for crate::LocalStore {
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
        // Validate signatures before using the inventory to protect files.
        self.signed_parquet_artifacts(case_id)?;
        self.parquet.clean_orphan_spools(case_id)
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
