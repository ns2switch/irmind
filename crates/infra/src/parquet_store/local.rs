pub(super) mod stream;
use super::{
    AppError, CancellationToken, CaseId, EvidenceHash, LargeCaseStore, ParquetArtifact,
    ParquetStore, Path, Seek, SeekFrom, SourceManifestV1, StreamingEventParser, UNIX_EPOCH,
    invalid_source, parse_hash, storage, storage_phase,
};

impl LargeCaseStore for ParquetStore {
    fn prepare_mapped_ingest(
        &self,
        request: irmind_app::MappedIngestRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<Option<Box<dyn irmind_app::PreparedMappedIngest>>, AppError> {
        self.prepare_direct(&request, cancel)
    }

    fn create_object_spool(
        &self,
        case_id: &CaseId,
        expected_bytes: u64,
    ) -> Result<tempfile::NamedTempFile, AppError> {
        self.create_private_object_spool(case_id, expected_bytes)
    }

    fn clean_orphan_spools(&self, case_id: &CaseId) -> Result<usize, AppError> {
        self.remove_orphaned_object_spools(case_id)
    }

    fn compact_artifacts(
        &self,
        case_id: &CaseId,
        sources: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<ParquetArtifact, AppError> {
        self.compact_signed_sources(case_id, sources, cancel)
    }

    fn verify_local_source(
        &self,
        source_root: &Path,
        manifest: &SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        manifest.validate().map_err(|_| invalid_source())?;
        let mut file = Self::open_source(source_root, &manifest.source)?;
        let metadata = file.metadata().map_err(storage)?;
        let (hash, size) = Self::hash_reader(&mut file, cancel)?;
        let modified = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_secs());
        if size != manifest.size
            || hash != parse_hash(&manifest.sha256)?
            || modified != manifest.modified_unix_seconds
        {
            return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
        }
        Ok(())
    }

    fn verify_artifact(
        &self,
        case_id: &CaseId,
        artifact: &ParquetArtifact,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        artifact.validate().map_err(|_| invalid_source())?;
        let case_dir = self.case_dir(case_id).map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotVerifyParquetArtifact,
            )
        })?;
        let mut file = irmind_fs::open_regular_no_follow(&case_dir, Path::new(&artifact.path()))
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                    irmind_app::AdapterStorageError::CannotVerifyParquetArtifact,
                ))
            })?;
        let (hash, size) = Self::hash_reader(&mut file, cancel).map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotVerifyParquetArtifact,
            )
        })?;
        if size != artifact.size() || hash != parse_hash(artifact.sha256())? {
            return Err(AppError::EvidenceMismatch(
                artifact.sha256().as_str().into(),
            ));
        }
        if matches!(artifact, ParquetArtifact::V3(_)) {
            file.seek(SeekFrom::Start(0)).map_err(storage)?;
            let reader =
                parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)
                    .map_err(storage)?;
            super::format::validate_schema(artifact, reader.schema())?;
            super::format::validate_row_count(
                artifact,
                reader.metadata().file_metadata().num_rows(),
            )?;
        }
        Ok(())
    }

    fn verify_copied_source(
        &self,
        case_id: &CaseId,
        manifest: &SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if !manifest.copied {
            return Err(invalid_source());
        }
        let case_dir = self.case_dir(case_id)?;
        let relative = format!("originals/{}", manifest.sha256.as_str());
        let mut file =
            irmind_fs::open_regular_no_follow(&case_dir, Path::new(&relative)).map_err(storage)?;
        let (hash, size) = Self::hash_reader(&mut file, cancel)?;
        if size != manifest.size || hash != parse_hash(&manifest.sha256)? {
            return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
        }
        Ok(())
    }

    fn rebuild_compare(
        &self,
        _case_id: &CaseId,
        _source_root: &Path,
        _sources: &[SourceManifestV1],
        _artifacts: &[ParquetArtifact],
        _parser: &dyn StreamingEventParser,
        _cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        Err(AppError::Policy(
            "full reconstruction requires the signed case store".into(),
        ))
    }
}

pub(super) fn verify_source_unchanged(
    source: &std::fs::File,
    metadata: &std::fs::Metadata,
    hash: &EvidenceHash,
) -> Result<(), AppError> {
    let after = source.metadata().map_err(|error| {
        storage_phase(
            storage(error),
            irmind_app::AdapterStorageError::CannotOpenParquetSource,
        )
    })?;
    if after.len() != metadata.len() || after.modified().ok() != metadata.modified().ok() {
        return Err(AppError::EvidenceMismatch(hash.as_str().into()));
    }
    Ok(())
}
