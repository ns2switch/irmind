use super::super::{
    AppError, BATCH_BYTES, BATCH_ROWS, BTreeMap, CancellationToken, ParquetStore, Partition,
    PartitionSinks, PreparedSource, RecordRow, StagedArtifact, batch_to_parquet, finish_parquet,
    invalid_source, storage,
};
use super::staging::{MAX_STAGED_ROW, StagedSource};
use super::{Allocator, BUILDER};
use irmind_app::{LargeCaseStore as _, LocalBatchRequest, PartitionProfile};
use std::io::{BufRead, Read};

const WRITER_PARTITIONS: usize = 16;
const MAX_ARTIFACTS: usize = 8192;

impl ParquetStore {
    pub(in crate::parquet_store) fn prepare_partition_batch(
        &self,
        request: &LocalBatchRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<Vec<PreparedSource>, AppError> {
        request.validate()?;
        let mut allocator = Allocator::from_signed(request.committed_artifacts, request.limits)?;
        let inputs =
            self.staging_inputs(request.case_id, request.source_root, request.relative_paths)?;
        self.prepare_ordered_sources(request, inputs, &mut allocator, cancel)
    }

    #[cfg(test)]
    pub(super) fn write_partition_source(
        &self,
        request: &LocalBatchRequest<'_>,
        source: StagedSource,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
        normalized_bytes: u64,
    ) -> Result<PreparedSource, AppError> {
        let prepared = self.replay_partition_source(request, source, allocator, cancel)?;
        self.publish_partition_source(
            request,
            prepared.source,
            prepared.staged,
            cancel,
            normalized_bytes,
        )
    }

    pub(super) fn replay_partition_source(
        &self,
        request: &LocalBatchRequest<'_>,
        mut source: StagedSource,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<PreparedPartition, AppError> {
        let replay = self
            .profile
            .as_ref()
            .map(|p| p.measure(super::super::PartitionPhase::Replay));
        let mut state = Writing::default();
        let dir = self.case_dir(request.case_id)?;
        let parser = request
            .parser
            .identity_for_source(&source.manifest.source)?;
        let mut reader =
            std::io::BufReader::new(super::super::HashingReader::new(source.spool.as_file_mut()));
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let mut bytes = Vec::new();
            (&mut reader)
                .take(MAX_STAGED_ROW + 1)
                .read_until(b'\n', &mut bytes)
                .map_err(storage)?;
            if bytes.is_empty() {
                break;
            }
            if bytes.len() as u64 > MAX_STAGED_ROW || bytes.last() != Some(&b'\n') {
                return Err(invalid_source());
            }
            let row: RecordRow = serde_json::from_slice(&bytes).map_err(storage)?;
            state.push_row(row, allocator, &dir, &source.manifest.sha256, parser)?;
        }
        if reader.into_inner().finish() != source.normalized_hash {
            return Err(AppError::EvidenceMismatch(
                source.manifest.sha256.as_str().into(),
            ));
        }
        state.finish(&dir, &source.manifest.sha256, parser)?;
        drop(replay);
        let parsed = super::ordered::ParsedSource {
            source: source.source,
            manifest: source.manifest,
            report: Some(source.report),
            initial: None,
            sample_hash: source.sample_hash,
            budget: 0,
        };
        PreparedPartition::new(parsed, state.staged, self.profile.clone())
    }

    pub(super) fn publish_partition_source(
        &self,
        request: &LocalBatchRequest<'_>,
        mut source: super::ordered::ParsedSource,
        staged: Vec<StagedArtifact>,
        cancel: &CancellationToken,
        normalized_bytes: u64,
    ) -> Result<PreparedSource, AppError> {
        let report = source.report.take().ok_or_else(invalid_source)?;
        let dir = self.case_dir(request.case_id)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        {
            let _verify = self
                .profile
                .as_ref()
                .map(|p| p.measure(super::super::PartitionPhase::SourceVerify));
            self.verify_local_source(request.source_root, &source.manifest, cancel)?;
        }
        let _publish = self
            .profile
            .as_ref()
            .map(|p| p.measure(super::super::PartitionPhase::Publish));
        if request.copy_original {
            self.copy_source(
                request.case_id,
                &mut source.source,
                &source.manifest.sha256,
                cancel,
            )?;
        }
        let staged = super::consolidate::consolidate(
            &dir,
            staged,
            cancel,
            self.profile.as_deref(),
            normalized_bytes,
        )?;
        let artifacts = self.finish_artifacts(request.case_id, staged)?;
        Ok(PreparedSource {
            manifest: source.manifest,
            artifacts,
            records: report.accepted,
            format_sample_sha256: source.sample_hash,
            parse_report: report,
        })
    }
}

pub(super) struct PreparedPartition {
    pub(super) source: super::ordered::ParsedSource,
    pub(super) staged: Vec<StagedArtifact>,
    pub(super) disk: super::temporary::DiskLease,
}

impl PreparedPartition {
    pub(super) fn new(
        source: super::ordered::ParsedSource,
        staged: Vec<StagedArtifact>,
        profile: Option<std::sync::Arc<super::super::ParquetProfile>>,
    ) -> Result<Self, AppError> {
        let mut disk = super::temporary::DiskLease::new(profile);
        for artifact in &staged {
            disk.add(artifact.manifest.size())?;
        }
        Ok(Self {
            source,
            staged,
            disk,
        })
    }
}

#[derive(Default)]
pub(super) struct Writing {
    grouped: BTreeMap<Partition, Vec<RecordRow>>,
    open: BTreeMap<Partition, PartitionSinks>,
    pub(super) staged: Vec<StagedArtifact>,
    keys: std::collections::BTreeSet<String>,
    segment: u32,
    rows: usize,
    bytes: usize,
}

impl Writing {
    pub(super) fn push_row(
        &mut self,
        mut row: RecordRow,
        allocator: &mut Allocator,
        dir: &std::path::Path,
        hash: &irmind_domain::EvidenceHash,
        parser: irmind_app::ParserIdentity<'_>,
    ) -> Result<(), AppError> {
        let profile = match row.profile {
            0 => PartitionProfile::Unpartitioned,
            1 => PartitionProfile::CloudAccountRegion,
            2 => PartitionProfile::EndpointHost,
            _ => return Err(invalid_source()),
        };
        let scope = allocator.assign(
            row.partition.utc_date(),
            profile,
            [&row.scope_account, &row.scope_region, &row.scope_host],
        )?;
        let key = scope.path_prefix().map_err(|_| invalid_source())?;
        if self.keys.len() == WRITER_PARTITIONS && !self.keys.contains(&key) {
            self.finish(dir, hash, parser)?;
        }
        self.keys.insert(key);
        row.partition = row.partition.with_scope(scope, self.segment);
        self.bytes = self.bytes.saturating_add(row.estimated_bytes());
        self.rows += 1;
        self.grouped
            .entry(row.partition.clone())
            .or_default()
            .push(row);
        if self.bytes >= BATCH_BYTES || self.rows >= BATCH_ROWS {
            self.flush(dir, hash)?;
        }
        Ok(())
    }
    fn flush(
        &mut self,
        dir: &std::path::Path,
        hash: &irmind_domain::EvidenceHash,
    ) -> Result<(), AppError> {
        batch_to_parquet(dir, hash, &mut self.grouped, &mut self.open, false)?;
        self.bytes = 0;
        self.rows = 0;
        Ok(())
    }
    pub(super) fn finish(
        &mut self,
        dir: &std::path::Path,
        hash: &irmind_domain::EvidenceHash,
        parser: irmind_app::ParserIdentity<'_>,
    ) -> Result<(), AppError> {
        self.flush(dir, hash)?;
        self.staged.extend(finish_parquet(
            std::mem::take(&mut self.open),
            hash,
            parser,
        )?);
        if self.staged.len() > MAX_ARTIFACTS {
            return Err(AppError::Fixed(
                irmind_app::FixedAppError::PolicyPartitionArtifactLimit,
            ));
        }
        self.segment = self.segment.checked_add(1).ok_or_else(invalid_source)?;
        self.keys.clear();
        Ok(())
    }
}

pub(in crate::parquet_store) fn supported_builder(version: &str) -> bool {
    matches!(version, super::super::writer::precise::BUILDER | BUILDER)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integrity_tests {
    use super::*;
    use irmind_mod_parser_json::JsonParser;

    #[test]
    fn a_changed_normalized_spool_cannot_publish_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let inputs = tempfile::tempdir().unwrap();
        std::fs::write(
            inputs.path().join("event.json"),
            br#"{"eventTime":"2026-11-01T00:00:00Z","host":"host-a"}"#,
        )
        .unwrap();
        let store = ParquetStore::open_precise(root.path()).unwrap();
        let id = irmind_domain::CaseId::parse("00000000-0000-0000-0000-000000000019").unwrap();
        let paths = ["event.json".into()];
        let mut input = store.staging_inputs(&id, inputs.path(), &paths).unwrap();
        let source = store
            .stage_source(
                &id,
                input.remove(0),
                &JsonParser,
                false,
                &CancellationToken::new(),
            )
            .unwrap();
        source.spool.as_file().set_len(0).unwrap();
        let request = LocalBatchRequest {
            case_id: &id,
            source_root: inputs.path(),
            relative_paths: &paths,
            copy_original: false,
            parser: &JsonParser,
            committed_artifacts: &[],
            limits: irmind_app::PartitionLimits::default(),
        };
        let mut allocation = Allocator::from_signed(&[], request.limits).unwrap();
        let result = store.write_partition_source(
            &request,
            source,
            &mut allocation,
            &CancellationToken::new(),
            0,
        );
        assert!(matches!(result, Err(AppError::EvidenceMismatch(_))));
        assert_eq!(
            std::fs::read_dir(store.spool_dir(&id).unwrap())
                .unwrap()
                .count(),
            0
        );
    }
}
