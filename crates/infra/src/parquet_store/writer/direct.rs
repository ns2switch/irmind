//! One final-file writer per compatible partition/schema with deterministic eviction.
use super::{
    AppError, ArtifactKind, ArtifactSink, BTreeMap, CancellationToken, EvidenceHash, Partition,
    Path, RecordBatch, RecordRow, StagedArtifact, invalid_source, precise, table_batches,
};
use crate::parquet_store::partitioning::Allocator;
mod finalize;
mod rows;
use rows::{bounded_rows, stable_rows};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

const OPEN_FILES: usize = 192;
const WRITER_MEMORY: usize = 128 * 1024 * 1024;
const FINAL_FILE_BYTES: usize = 64 * 1024 * 1024;
const FINAL_ROW_GROUPS: usize = 64;
const FILE_SOURCES: usize = 128;
const BUFFER_BYTES: usize = 1024 * 1024;
const ROW_GROUP: usize = 8192;
type Key = (Partition, ArtifactKind);
struct Live {
    sink: ArtifactSink,
    sources: BTreeSet<EvidenceHash>,
    touched: u64,
}
pub(in crate::parquet_store) struct DirectWriting {
    grouped: BTreeMap<Partition, Vec<RecordRow>>,
    buffered: usize,
    inflight: usize,
    profile: Option<Arc<crate::parquet_store::ParquetProfile>>,
    open: BTreeMap<Key, Live>,
    segments: BTreeMap<Key, u32>,
    clock: u64,
    staged: Vec<StagedArtifact>,
    hash: EvidenceHash,
    parser: (String, String),
    routes: BTreeMap<String, Option<irmind_domain::MappingIdentityV1>>,
    sources: BTreeMap<String, String>,
}
impl DirectWriting {
    pub(in crate::parquet_store) fn new(
        hash: EvidenceHash,
        parser: irmind_app::ParserIdentity<'_>,
        routes: BTreeMap<String, Option<irmind_domain::MappingIdentityV1>>,
        profile: Option<Arc<crate::parquet_store::ParquetProfile>>,
    ) -> Self {
        Self {
            grouped: BTreeMap::new(),
            buffered: 0,
            inflight: 0,
            profile,
            open: BTreeMap::new(),
            segments: BTreeMap::new(),
            clock: 0,
            staged: Vec::new(),
            hash,
            parser: (parser.name.into(), parser.version.into()),
            routes,
            sources: BTreeMap::new(),
        }
    }
    pub(in crate::parquet_store) fn register_source(
        &mut self,
        hash: &EvidenceHash,
        name: &str,
    ) -> Result<(), AppError> {
        if self.sources.len() == FILE_SOURCES && !self.sources.contains_key(hash.as_str()) {
            return Err(invalid_source());
        }
        match self.sources.get(hash.as_str()) {
            Some(existing) if existing != name => Err(AppError::Fixed(
                irmind_app::FixedAppError::PolicyMappedSourceAlreadyIndexed,
            )),
            Some(_) => Ok(()),
            None => {
                self.sources.insert(hash.as_str().into(), name.into());
                Ok(())
            }
        }
    }
    pub(in crate::parquet_store) fn push(
        &mut self,
        mut row: RecordRow,
        allocator: &mut Allocator,
        dir: &Path,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let profile = match row.profile {
            0 => irmind_app::PartitionProfile::Unpartitioned,
            1 => irmind_app::PartitionProfile::CloudAccountRegion,
            2 => irmind_app::PartitionProfile::EndpointHost,
            _ => return Err(invalid_source()),
        };
        let scope = allocator.assign(
            row.partition.utc_date(),
            profile,
            [&row.scope_account, &row.scope_region, &row.scope_host],
        )?;
        row.partition = row.partition.with_scope(scope, 0);
        self.buffered = self.buffered.saturating_add(row.estimated_bytes());
        self.grouped
            .entry(row.partition.clone())
            .or_default()
            .push(row);
        if self.buffered >= BUFFER_BYTES {
            self.flush(dir, cancel)?;
        }
        Ok(())
    }
    fn flush(&mut self, dir: &Path, cancel: &CancellationToken) -> Result<(), AppError> {
        let mut grouped = std::mem::take(&mut self.grouped);
        let active = self
            .open
            .keys()
            .map(|(partition, _)| partition.clone())
            .collect::<BTreeSet<_>>();
        let mut keys = grouped.keys().cloned().collect::<Vec<_>>();
        keys.sort_by_key(|partition| (!active.contains(partition), partition.clone()));
        for partition in keys {
            let mut rows = grouped.remove(&partition).ok_or_else(invalid_source)?;
            let started = Instant::now();
            stable_rows(&mut rows, &self.sources)?;
            let (events, entities, coobs) = table_batches(&rows)?;
            if let Some(profile) = &self.profile {
                profile.record_row(started.elapsed());
            }
            self.inflight = events
                .get_array_memory_size()
                .saturating_add(entities.get_array_memory_size())
                .saturating_add(coobs.get_array_memory_size());
            if self.inflight > WRITER_MEMORY {
                return Err(AppError::Policy(
                    "direct row batch exceeds the bounded writer budget".into(),
                ));
            }
            for (kind, batch) in [
                (ArtifactKind::Events, events),
                (ArtifactKind::Entities, entities),
            ] {
                self.append(dir, &partition, kind, &batch, cancel)?;
            }
            self.append(
                dir,
                &partition,
                ArtifactKind::Coobservations,
                &coobs,
                cancel,
            )?;
        }
        self.buffered = 0;
        self.inflight = 0;
        Ok(())
    }
    fn append(
        &mut self,
        dir: &Path,
        partition: &Partition,
        kind: ArtifactKind,
        batch: &RecordBatch,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let started = Instant::now();
        let key = (partition.clone(), kind);
        let mut start = 0;
        while start < batch.num_rows() {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            self.reserve(dir, &key, &batch.slice(start, 1), cancel)?;
            let existing = &self.open.get(&key).ok_or_else(invalid_source)?.sources;
            let (end, sources) = bounded_rows(batch, start, Some(existing), |sources| {
                self.fits(&key, sources)
            })?;
            if end == start {
                if existing.is_empty() {
                    return Err(invalid_source());
                }
                self.close(&key, cancel)?;
                continue;
            }
            let slice = batch.slice(start, end - start);
            start = end;
            self.clock += 1;
            let live = self.open.get_mut(&key).ok_or_else(invalid_source)?;
            live.sources.extend(sources);
            live.touched = self.clock;
            live.sink.append(&slice)?;
            let writer = live.sink.writer.as_ref().ok_or_else(invalid_source)?;
            if writer.flushed_row_groups().len() >= FINAL_ROW_GROUPS
                || writer.bytes_written() >= FINAL_FILE_BYTES
            {
                self.close(&key, cancel)?;
            }
            self.trim(cancel)?;
            self.measure_staging();
        }
        if let Some(profile) = &self.profile {
            profile.record_parquet(started.elapsed());
        }
        Ok(())
    }
    fn fits(&self, key: &Key, sources: &BTreeSet<EvidenceHash>) -> Result<bool, AppError> {
        use irmind_domain::{
            ArtifactPipelineV1, MappingBindingV1, MappingInputRefV1, SourceDecoderIdentityV1,
        };
        let live = self.open.get(key).ok_or_else(invalid_source)?;
        let parser = irmind_app::ParserIdentity {
            name: &self.parser.0,
            version: &self.parser.1,
        };
        let mut core = precise::manifest(&live.sink, &self.hash, parser, 1, &[0; 32])?;
        core.source_hashes = sources.iter().cloned().collect();
        let mapping = key
            .0
            .mapping_route()
            .and_then(|route| self.routes.get(route))
            .ok_or_else(invalid_source)?;
        let decoder = SourceDecoderIdentityV1::try_new(&self.parser.0, &self.parser.1)
            .map_err(|_| invalid_source())?;
        let zero = EvidenceHash::from_bytes([0; 32]);
        let bindings = sources
            .iter()
            .map(|source| {
                Ok(MappingBindingV1::new(
                    MappingInputRefV1::try_new(source.clone(), zero.clone(), 1)
                        .map_err(|_| invalid_source())?,
                    zero.clone(),
                    zero.clone(),
                    decoder.clone(),
                    mapping.clone(),
                ))
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let pipeline = ArtifactPipelineV1::mapped(bindings, 1).map_err(|_| invalid_source())?;
        Ok(irmind_domain::ParquetArtifactV3::try_new(core, pipeline).is_ok())
    }
    fn reserve(
        &mut self,
        dir: &Path,
        key: &Key,
        batch: &RecordBatch,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if self.open.contains_key(key) {
            return Ok(());
        }
        if self.open.len() >= OPEN_FILES {
            self.evict(cancel)?;
        }
        let segment = self.segments.entry(key.clone()).or_default();
        let mut partition = key.0.clone();
        partition.segment = *segment;
        *segment = segment.checked_add(1).ok_or_else(invalid_source)?;
        let sink = ArtifactSink::new(
            dir,
            &self.hash,
            partition,
            batch,
            key.1,
            self.profile.clone(),
        )?;
        self.open.insert(
            key.clone(),
            Live {
                sink,
                sources: BTreeSet::new(),
                touched: self.clock,
            },
        );
        Ok(())
    }
    fn trim(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        while self
            .open
            .values()
            .map(|live| {
                live.sink.writer.as_ref().map_or(0, |w| {
                    w.memory_size()
                        .saturating_add(w.flushed_row_groups().len() * 32 * 1024)
                })
            })
            .sum::<usize>()
            .saturating_add(self.buffered)
            .saturating_add(self.inflight)
            > WRITER_MEMORY
        {
            self.evict(cancel)?;
        }
        Ok(())
    }
    fn measure_staging(&self) {
        if let Some(profile) = &self.profile {
            use std::sync::atomic::Ordering;
            let closed = self.staged.iter().map(|a| a.manifest.size).sum::<u64>();
            let open = self
                .open
                .values()
                .filter_map(|live| live.sink.writer.as_ref())
                .map(|writer| writer.bytes_written() as u64)
                .sum::<u64>();
            profile.record_staging_peak(
                profile
                    .staging_live
                    .load(Ordering::Relaxed)
                    .saturating_add(closed)
                    .saturating_add(open),
            );
        }
    }
    fn evict(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        let key = self
            .open
            .iter()
            .min_by_key(|(key, live)| (live.touched, *key))
            .map(|(key, _)| key.clone())
            .ok_or_else(invalid_source)?;
        self.close(&key, cancel)
    }
    fn close(&mut self, key: &Key, cancel: &CancellationToken) -> Result<(), AppError> {
        if let Some(live) = self.open.remove(key) {
            let output = finalize::finish_live(live, &self.hash, self.parser_identity(), cancel)?;
            self.record_finished(output)?;
        }
        Ok(())
    }

    fn parser_identity(&self) -> irmind_app::ParserIdentity<'_> {
        irmind_app::ParserIdentity {
            name: &self.parser.0,
            version: &self.parser.1,
        }
    }

    fn record_finished(&mut self, output: Option<StagedArtifact>) -> Result<(), AppError> {
        if let Some(output) = output {
            self.staged.push(output);
        }
        if self.staged.len() > 8192 {
            return Err(invalid_source());
        }
        Ok(())
    }

    pub(in crate::parquet_store) fn finish(
        mut self,
        dir: &Path,
        workers: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<StagedArtifact>, AppError> {
        self.flush(dir, cancel)?;
        let started = Instant::now();
        self.finish_partitions(workers, cancel)?;
        self.staged
            .sort_by(|a, b| a.manifest.path.cmp(&b.manifest.path));
        self.measure_staging();
        if let Some(profile) = &self.profile {
            let elapsed = started.elapsed();
            profile.record_parquet(elapsed);
            profile.record_partition_finalize(elapsed);
        }
        Ok(self.staged)
    }
}
