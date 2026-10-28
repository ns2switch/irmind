mod stream;
use stream::{StreamInput, initial_hash, stream_records};

use super::{
    AppError, BATCH_BYTES, BATCH_ROWS, BTreeMap, CancellationToken, CaseId, EvidenceHash, File,
    GraphRecord, HashingReader, Instant, LargeCaseStore, OpenOptions, ParquetArtifactV1,
    ParquetProfile, ParquetStore, Partition, PartitionSinks, Path, PreparedSource, RecordRow, Seek,
    SeekFrom, SourceManifestV1, StreamingEventParser, TempWorkspace, UNIX_EPOCH, Write,
    batch_to_parquet, finish_parquet, invalid_source, parse_hash, storage, storage_phase,
};

impl LargeCaseStore for ParquetStore {
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
        let hash_value =
            EvidenceHash::parse(&irmind_app::hex(&hash)).map_err(|_| invalid_source())?;
        let conversion_started = Instant::now();
        let case_dir = self.case_dir(case_id).map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotPrepareParquetOutput,
            )
        })?;
        let (records, open) = stream_records(StreamInput {
            source: &mut source,
            relative_path,
            hash,
            hash_value: &hash_value,
            size,
            case_dir: &case_dir,
            parser,
            cancel,
            profile: self.profile.as_deref(),
        })?;
        let after = source.metadata().map_err(|error| {
            storage_phase(
                storage(error),
                irmind_app::AdapterStorageError::CannotOpenParquetSource,
            )
        })?;
        if after.len() != metadata.len() || after.modified().ok() != metadata.modified().ok() {
            return Err(AppError::EvidenceMismatch(hash_value.as_str().into()));
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let parquet_started = Instant::now();
        if copy_original {
            self.copy_source(case_id, &mut source, &hash_value, cancel)?;
        }
        let staged = finish_parquet(open, &hash_value).map_err(|error| {
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
            records,
        })
    }

    fn prepare_legacy_evidence(
        &self,
        case_id: &CaseId,
        hash: &str,
        bytes: &[u8],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<Vec<ParquetArtifactV1>, AppError> {
        let hash = EvidenceHash::parse(hash).map_err(|_| invalid_source())?;
        if bytes.len() > 50_000_000 || irmind_app::hex(&irmind_app::sha256(bytes)) != hash.as_str()
        {
            return Err(AppError::EvidenceMismatch(hash.as_str().into()));
        }
        let temporary = TempWorkspace::new(&self.root)?;
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
        let prepared = self.prepare_local(
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
        sources: &[ParquetArtifactV1],
        cancel: &CancellationToken,
    ) -> Result<ParquetArtifactV1, AppError> {
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
        artifact: &ParquetArtifactV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        artifact.validate().map_err(|_| invalid_source())?;
        let case_dir = self.case_dir(case_id).map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotVerifyParquetArtifact,
            )
        })?;
        let mut file = irmind_fs::open_regular_no_follow(&case_dir, Path::new(&artifact.path))
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
        if size != artifact.size || hash != parse_hash(&artifact.sha256)? {
            return Err(AppError::EvidenceMismatch(artifact.sha256.as_str().into()));
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
        artifacts: &[ParquetArtifactV1],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let temporary = TempWorkspace::new(&self.root)?;
        let fresh = ParquetStore::open(&temporary.path)?;
        let mut checked = 0usize;
        let mut rebuilt = Vec::new();
        for source in sources {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let prepared =
                fresh.prepare_local(case_id, source_root, &source.source, false, parser, cancel)?;
            if prepared.manifest.sha256 != source.sha256 || prepared.manifest.size != source.size {
                return Err(AppError::EvidenceMismatch(source.sha256.as_str().into()));
            }
            let mut actual = prepared.artifacts;
            actual.sort_by(|a, b| a.path.cmp(&b.path));
            let mut signed = artifacts
                .iter()
                .filter(|artifact| {
                    artifact.source_hashes.len() == 1
                        && artifact.parser_version == "json-stream-v2"
                        && artifact.source_hashes.contains(&source.sha256)
                })
                .cloned()
                .collect::<Vec<_>>();
            signed.sort_by(|a, b| a.path.cmp(&b.path));
            if actual != signed {
                return Err(AppError::EvidenceMismatch(source.sha256.as_str().into()));
            }
            rebuilt.extend(actual);
            checked += 1;
        }
        let source_hashes = sources
            .iter()
            .map(|source| source.sha256.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for signed in artifacts.iter().filter(|artifact| {
            artifact.source_hashes.len() > 1
                && artifact
                    .source_hashes
                    .iter()
                    .all(|hash| source_hashes.contains(hash))
        }) {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let inputs = rebuilt
                .iter()
                .filter(|artifact: &&ParquetArtifactV1| {
                    artifact.partition_date == signed.partition_date
                        && artifact.partition_account == signed.partition_account
                        && artifact.partition_region == signed.partition_region
                        && artifact.schema_version == signed.schema_version
                        && signed.source_hashes.contains(&artifact.source_hashes[0])
                })
                .cloned()
                .collect::<Vec<_>>();
            let actual = fresh.compact_signed_sources(case_id, &inputs, cancel)?;
            if &actual != signed {
                return Err(AppError::EvidenceMismatch(signed.sha256.as_str().into()));
            }
        }
        Ok(checked)
    }
}
