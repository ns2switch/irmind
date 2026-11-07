pub(super) mod stream;
use stream::{StreamInput, initial_hash, stream_records};

use super::{
    AppError, BATCH_BYTES, BATCH_ROWS, BTreeMap, CancellationToken, CaseId, EvidenceHash, File,
    GraphRecord, HashingReader, Instant, LargeCaseStore, OpenOptions, ParquetArtifact,
    ParquetProfile, ParquetStore, ParseReport, Partition, PartitionSinks, Path, PreparedSource,
    RecordRow, Seek, SeekFrom, SourceManifestV1, StreamingEventParser, TempWorkspace, UNIX_EPOCH,
    Write, batch_to_parquet, finish_parquet, invalid_source, parse_hash, storage, storage_phase,
};
use std::io::Read as _;

impl LargeCaseStore for ParquetStore {
    fn prepare_artifact_migration(
        &self,
        request: irmind_app::ArtifactMigrationRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn irmind_app::PreparedArtifactMigration>, AppError> {
        self.prepare_migration(&request, cancel)
    }

    fn prepare_local_batch(
        &self,
        request: irmind_app::LocalBatchRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<Vec<PreparedSource>, AppError> {
        request.validate()?;
        if self.precise_time {
            return self.prepare_partition_batch(&request, cancel);
        }
        std::thread::scope(|scope| {
            let workers = request
                .relative_paths
                .iter()
                .map(|path| {
                    scope.spawn(|| {
                        self.prepare_local(
                            request.case_id,
                            request.source_root,
                            path,
                            request.copy_original,
                            request.parser,
                            cancel,
                        )
                    })
                })
                .collect::<Vec<_>>();
            let outcomes = workers
                .into_iter()
                .map(|w| w.join().map_err(|_| invalid_source())?)
                .collect::<Vec<_>>();
            outcomes.into_iter().collect()
        })
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

    fn prepare_local(
        &self,
        case_id: &CaseId,
        source_root: &Path,
        relative_path: &str,
        copy_original: bool,
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<PreparedSource, AppError> {
        let mut source = Self::open_source(source_root, relative_path).map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotOpenParquetSource,
            )
        })?;
        let (metadata, hash, size) = initial_hash(&mut source, cancel, self.profile.as_deref())?;
        source.seek(SeekFrom::Start(0)).map_err(storage)?;
        let mut format_sample = Vec::new();
        (&mut source)
            .take(64 * 1024)
            .read_to_end(&mut format_sample)
            .map_err(storage)?;
        let format_sample_sha256 = irmind_app::sha256(&format_sample);
        let hash_value =
            EvidenceHash::parse(&irmind_app::hex(&hash)).map_err(|_| invalid_source())?;
        let conversion_started = Instant::now();
        let case_dir = self.case_dir(case_id).map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotPrepareParquetOutput,
            )
        })?;
        let (parse_report, open) = stream_records(StreamInput {
            source: &mut source,
            sample: &format_sample,
            relative_path,
            hash,
            hash_value: &hash_value,
            size,
            case_dir: &case_dir,
            parser,
            cancel,
            profile: self.profile.as_deref(),
            legacy_entities: self.legacy_entities,
            precise_time: self.precise_time,
        })?;
        verify_source_unchanged(&source, &metadata, &hash_value)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let parquet_started = Instant::now();
        if copy_original {
            self.copy_source(case_id, &mut source, &hash_value, cancel)?;
        }
        let staged = finish_parquet(
            open,
            &hash_value,
            parser.identity_for_source(relative_path)?,
        )
        .map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotPrepareParquetOutput,
            )
        })?;
        let artifacts = self.finish_artifacts(case_id, staged).map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotPublishParquetArtifact,
            )
        })?;
        if let Some(profile) = &self.profile {
            profile.record_parquet(parquet_started.elapsed());
        }
        if let Some(profile) = &self.profile {
            profile.record_conversion(conversion_started.elapsed());
        }
        let manifest =
            Self::source_manifest(relative_path, &metadata, size, hash_value, copy_original)?;
        Ok(PreparedSource {
            manifest,
            artifacts,
            records: parse_report.accepted,
            format_sample_sha256,
            parse_report,
        })
    }

    fn prepare_legacy_evidence(
        &self,
        case_id: &CaseId,
        hash: &str,
        bytes: &[u8],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<Vec<ParquetArtifact>, AppError> {
        let hash = EvidenceHash::parse(hash).map_err(|_| invalid_source())?;
        if bytes.len() > 50_000_000 || irmind_app::hex(&irmind_app::sha256(bytes)) != hash.as_str()
        {
            return Err(AppError::EvidenceMismatch(hash.as_str().into()));
        }
        let temporary = TempWorkspace::new(&self.spool_dir(case_id)?)?;
        let input = temporary.path.join(hash.as_str());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&input).map_err(storage)?;
        irmind_fs::private_file(&input).map_err(storage)?;
        file.write_all(bytes).map_err(storage)?;
        file.sync_all().map_err(storage)?;
        drop(file);
        let mut legacy = Self::open(self.root.parent().ok_or_else(invalid_source)?)?;
        legacy.legacy_entities = self.legacy_entities;
        let prepared = legacy.prepare_local(
            case_id,
            &temporary.path,
            hash.as_str(),
            false,
            parser,
            cancel,
        )?;
        if prepared.manifest.sha256 != hash {
            return Err(AppError::EvidenceMismatch(hash.as_str().into()));
        }
        Ok(prepared.artifacts)
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
        case_id: &CaseId,
        source_root: &Path,
        sources: &[SourceManifestV1],
        artifacts: &[ParquetArtifact],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.rebuild_generations(case_id, source_root, sources, artifacts, parser, cancel)
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

impl ParquetStore {
    pub(super) fn replay_mode(&mut self, source: &SourceManifestV1, artifacts: &[ParquetArtifact]) {
        self.common_events=artifacts.iter().any(|a|matches!(a,ParquetArtifact::V2(v) if v.schema.is_common() && v.source_hashes.contains(&source.sha256)));
        self.precise_time = artifacts.iter().any(|a| {
            matches!(a, ParquetArtifact::V2(_)) && a.source_hashes().contains(&source.sha256)
        });
        self.legacy_entities = artifacts.iter().any(|artifact| {
            artifact.source_hashes().len() == 1
                && artifact.source_hashes()[0] == source.sha256
                && artifact.schema_version() == "irmind-entities-v1"
        });
    }

    pub(super) fn replay_prepared(
        &self,
        request: irmind_app::LocalBatchRequest<'_>,
        source: &SourceManifestV1,
        signed: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<PreparedSource, AppError> {
        let partitioned = signed.iter().any(|a| matches!(a, ParquetArtifact::V2(v)
            if matches!(v.builder_version.as_str(),super::partitioning::BUILDER|super::common_format::BUILDER) && v.source_hashes.contains(&source.sha256)));
        if partitioned {
            self.prepare_local_batch(request, cancel)?
                .pop()
                .ok_or_else(invalid_source)
        } else {
            self.prepare_local(
                request.case_id,
                request.source_root,
                &source.source,
                false,
                request.parser,
                cancel,
            )
        }
    }
}
