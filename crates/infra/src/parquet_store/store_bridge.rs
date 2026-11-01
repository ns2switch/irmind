use super::{
    AppError, CancellationToken, CaseId, LargeCaseStore, ParquetArtifactV1, Path, PreparedSource,
    SourceManifestV1, StreamingEventParser,
};

impl LargeCaseStore for crate::LocalStore {
    fn create_object_spool(
        &self,
        case_id: &CaseId,
        expected_bytes: u64,
    ) -> Result<tempfile::NamedTempFile, AppError> {
        self.parquet.create_object_spool(case_id, expected_bytes)
    }

    fn clean_orphan_spools(&self, case_id: &CaseId) -> Result<usize, AppError> {
        self.parquet.clean_orphan_spools(case_id)
    }

    fn prepare_local(
        &self,
        case_id: &CaseId,
        source_root: &Path,
        relative_path: &str,
        copy_original: bool,
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<PreparedSource, AppError> {
        self.parquet.prepare_local(
            case_id,
            source_root,
            relative_path,
            copy_original,
            parser,
            cancel,
        )
    }

    fn prepare_legacy_evidence(
        &self,
        case_id: &CaseId,
        hash: &str,
        bytes: &[u8],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<Vec<ParquetArtifactV1>, AppError> {
        self.parquet
            .prepare_legacy_evidence(case_id, hash, bytes, parser, cancel)
    }

    fn compact_artifacts(
        &self,
        case_id: &CaseId,
        sources: &[ParquetArtifactV1],
        cancel: &CancellationToken,
    ) -> Result<ParquetArtifactV1, AppError> {
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
        artifact: &ParquetArtifactV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.parquet.verify_artifact(case_id, artifact, cancel)
    }

    fn rebuild_compare(
        &self,
        case_id: &CaseId,
        source_root: &Path,
        sources: &[SourceManifestV1],
        artifacts: &[ParquetArtifactV1],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.parquet
            .rebuild_compare(case_id, source_root, sources, artifacts, parser, cancel)
    }
}
