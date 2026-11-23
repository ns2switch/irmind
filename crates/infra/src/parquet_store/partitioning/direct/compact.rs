//! Authenticate native frame locators, order them, then decode and map once.
mod runs;

use super::super::{
    Allocator,
    staging::{Input, MAX_STAGED_ROW, normalized_source_limit, source_sample},
};
use super::{
    AppError, CancellationToken, DirectWriting, MappedIngestRequest, ParquetStore, invalid_source,
};
use crate::parquet_store::{
    HashingReader, PartitionPhase, local::verify_source_unchanged, mapped, storage,
};
use irmind_app::{
    MappedSourceAcquisition, ParseReport,
    source_mapping::{
        CompactRecordLocator, ReorderedRecords, SourceFileInput, SourceInput, SourceMetadata,
        SourceRecordAccumulator, SourceReferenceV1,
    },
};
use irmind_domain::EvidenceHash;
use std::io::{self, Seek as _, Write};

type Initial = (std::fs::Metadata, [u8; 32], u64);
const RUN_RECORDS: usize = 65_536;

pub(super) enum Choice {
    Fallback(Input, Box<Initial>),
    Stream(Input),
    Compact(Box<Planned>),
}

pub(super) struct Planned {
    input: Input,
    initial: Initial,
    runs: Vec<runs::Run>,
    count: u64,
    sample_hash: [u8; 32],
}

fn compact_id(id: irmind_app::ParserIdentity<'_>) -> bool {
    (id.name, id.version) == ("parser-azure-flow", "azure-flow-source-v1")
}

pub(super) fn plan(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    mut input: Input,
    initial: Initial,
    cancel: &CancellationToken,
) -> Result<Choice, AppError> {
    let id = request.parser.identity_for_source(&input.path)?;
    if !compact_id(id)
        || request.parser.timestamp_context().is_some()
        || request.parser.cluster_context().is_some()
        || store.capture_origin.is_some()
    {
        return Ok(Choice::Fallback(input, Box::new(initial)));
    }
    let decoder = store
        .mapping_catalog
        .as_ref()
        .ok_or_else(invalid_source)?
        .decoder(id.name, id.version)?;
    let Some(ordering) = decoder.compact_ordering() else {
        return Ok(Choice::Fallback(input, Box::new(initial)));
    };
    let _stage = store
        .profile
        .as_ref()
        .map(|p| p.measure(PartitionPhase::Stage));
    let logical = request.parser.logical_source(&input.path);
    let reference = SourceReferenceV1::file(logical).map_err(|_| invalid_source())?;
    let metadata = SourceMetadata {
        source: &reference,
        evidence_hash: initial.1,
        time_context: None,
        cluster_context: None,
        cancel,
    };
    let sample_hash = irmind_app::sha256(&source_sample(&mut input.file)?);
    input.file.rewind().map_err(storage)?;
    let mut reader = HashingReader::new(&mut input.file);
    let mut locator_runs = LocatorRuns::default();
    let result = ordering.scan(
        SourceInput {
            metadata,
            reader: &mut reader,
        },
        &mut |locator| locator_runs.push(store, request, locator, initial.2, input.budget, cancel),
    );
    if reader.io_failed {
        return Err(storage("compact Azure read"));
    }
    match result {
        Ok(false) => return Ok(Choice::Fallback(input, Box::new(initial))),
        Err(AppError::Cancelled) if locator_runs.too_large && !cancel.is_cancelled() => {
            return Ok(Choice::Fallback(input, Box::new(initial)));
        }
        other => {
            other?;
        }
    }
    reader.drain(cancel)?;
    if reader.bytes != initial.2 || reader.finish() != initial.1 {
        return Err(AppError::EvidenceMismatch(irmind_app::hex(&initial.1)));
    }
    if !locator_runs.disordered {
        return Ok(Choice::Stream(input));
    }
    let count = locator_runs.count;
    Ok(Choice::Compact(Box::new(Planned {
        input,
        initial,
        runs: locator_runs.finish(store, request.case_id, cancel)?,
        count,
        sample_hash,
    })))
}

#[derive(Default)]
struct LocatorRuns {
    batch: Vec<CompactRecordLocator>,
    pending: Vec<runs::Run>,
    count: u64,
    previous: Option<irmind_domain::StableRecordKey<'static>>,
    disordered: bool,
    too_large: bool,
}

impl LocatorRuns {
    fn push(
        &mut self,
        store: &ParquetStore,
        request: &MappedIngestRequest<'_>,
        locator: CompactRecordLocator,
        source_bytes: u64,
        budget: u64,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if locator.index != self.count
            || locator.frame_len == 0
            || locator
                .frame_start
                .checked_add(u64::from(locator.frame_len))
                .is_none_or(|end| end > source_bytes)
        {
            return Err(invalid_source());
        }
        self.count += 1;
        if self.count * (2 * runs::BYTES + ReorderedRecords::SLOT_BYTES) > budget {
            self.too_large = true;
            return Err(AppError::Cancelled);
        }
        let key = runs::key(locator);
        if let Some(old) = self.previous {
            self.disordered |= irmind_domain::compare_record_keys(old, key, false)
                .map_err(|_| invalid_source())?
                .is_gt();
        }
        self.previous = Some(key);
        self.batch.push(locator);
        if self.batch.len() == RUN_RECORDS {
            self.pending
                .push(write_run(store, request.case_id, &mut self.batch, cancel)?);
        }
        Ok(())
    }

    fn finish(
        mut self,
        store: &ParquetStore,
        case: &irmind_domain::CaseId,
        cancel: &CancellationToken,
    ) -> Result<Vec<runs::Run>, AppError> {
        if !self.batch.is_empty() {
            self.pending
                .push(write_run(store, case, &mut self.batch, cancel)?);
        }
        Ok(self.pending)
    }
}

fn write_run(
    store: &ParquetStore,
    case: &irmind_domain::CaseId,
    batch: &mut Vec<CompactRecordLocator>,
    cancel: &CancellationToken,
) -> Result<runs::Run, AppError> {
    batch.sort_unstable_by_key(|locator| runs::order(*locator));
    let mut writer = runs::Writer::new(store, case)?;
    for locator in batch.drain(..) {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        writer.push(locator)?;
    }
    writer.finish(store, 0, 0)
}

pub(super) fn replay(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    source: Planned,
    writing: &mut DirectWriting,
    allocator: &mut Allocator,
    cancel: &CancellationToken,
) -> Result<MappedSourceAcquisition, AppError> {
    let Planned {
        mut input,
        initial: (snapshot, digest, size),
        runs,
        count,
        sample_hash,
    } = source;
    let id = request.parser.identity_for_source(&input.path)?;
    let hash = EvidenceHash::from_bytes(digest);
    let logical = request.parser.logical_source(&input.path);
    let reference = SourceReferenceV1::file(logical).map_err(|_| invalid_source())?;
    let metadata = SourceMetadata {
        source: &reference,
        evidence_hash: digest,
        time_context: None,
        cluster_context: None,
        cancel,
    };
    let catalog = store
        .mapping_catalog
        .as_ref()
        .ok_or_else(invalid_source)?
        .for_decoder(id);
    let decoder = catalog.decoder(id.name, id.version)?;
    let ordering = decoder.compact_ordering().ok_or_else(invalid_source)?;
    let routes = mapped::projection_routes_for_direct(&catalog)?;
    let (run, mut receipts, _disk) = prepare_replay(store, request.case_id, runs, count, cancel)?;
    let mut account = ReorderedRecords::new(
        SourceRecordAccumulator::new(metadata, id, size, &catalog)?,
        count,
    )?;
    writing.register_source(&hash, logical)?;
    let root = store.case_dir(request.case_id)?;
    {
        let _replay = store
            .profile
            .as_ref()
            .map(|p| p.measure(PartitionPhase::Replay));
        let mut replay = ordering.replay(SourceFileInput {
            metadata,
            file: &mut input.file,
        });
        let mut reader = run.reader()?;
        let mut normalized = CountBytes::default();
        while let Some(locator) = reader.next(cancel)? {
            let record = replay.read(locator).map_err(|error| match error {
                AppError::EvidenceMismatch(_) => {
                    super::read::source_changed(input.path.clone()).unwrap_or_else(|error| error)
                }
                other => other,
            })?;
            let mapped = account.accept(record, receipts.as_file_mut())?;
            let row = mapped::project_row(&mapped, id, &hash, &routes)?;
            ensure_row_matches_locator(&row, locator)?;
            normalized.charge(&row, input.budget)?;
            writing.push(row, allocator, &root, cancel)?;
        }
    }
    verify_replayed_source(&mut input, &snapshot, &hash, size, cancel)?;
    let report = ParseReport {
        accepted: usize::try_from(count).map_err(storage)?,
        rejected: 0,
        samples: vec![],
    };
    let record_set = account.finish(receipts.as_file_mut(), &report)?;
    Ok(MappedSourceAcquisition {
        manifest: ParquetStore::source_manifest(
            &input.path,
            &snapshot,
            size,
            hash,
            request.copy_original,
        )?,
        report,
        format_sample_sha256: sample_hash,
        decoded: record_set,
    })
}

fn verify_replayed_source(
    input: &mut Input,
    snapshot: &std::fs::Metadata,
    hash: &EvidenceHash,
    size: u64,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let (current, live_size) = ParquetStore::hash_reader(&mut input.file, cancel)?;
    if &EvidenceHash::from_bytes(current) != hash || live_size != size {
        return Err(super::read::source_changed(input.path.clone())?);
    }
    verify_source_unchanged(&input.file, snapshot, hash)
}

type ReplayScratch = (
    runs::Run,
    tempfile::NamedTempFile,
    super::super::temporary::DiskLease,
);

fn prepare_replay(
    store: &ParquetStore,
    case: &irmind_domain::CaseId,
    runs: Vec<runs::Run>,
    count: u64,
    cancel: &CancellationToken,
) -> Result<ReplayScratch, AppError> {
    let run = {
        let _sort = store
            .profile
            .as_ref()
            .map(|p| p.measure(PartitionPhase::Sort));
        runs::merge(store, case, runs, cancel)?
    };
    let bytes = count * ReorderedRecords::SLOT_BYTES;
    let receipts = store.create_private_object_spool(case, bytes)?;
    let mut lease = super::super::temporary::DiskLease::new(store.profile.clone());
    lease.add(bytes)?;
    Ok((run, receipts, lease))
}

fn ensure_row_matches_locator(
    row: &crate::parquet_store::RecordRow,
    locator: CompactRecordLocator,
) -> Result<(), AppError> {
    let key = row.sort_key();
    if key.record_index != locator.index
        || key.instant != Some(locator.time.instant())
        || key.source_offset.is_some()
    {
        return Err(invalid_source());
    }
    Ok(())
}

#[derive(Default)]
struct CountBytes(u64);
impl Write for CountBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("normalized size overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl CountBytes {
    fn charge(
        &mut self,
        row: &crate::parquet_store::RecordRow,
        budget: u64,
    ) -> Result<(), AppError> {
        let before = self.0;
        serde_json::to_writer(&mut *self, row).map_err(storage)?;
        self.write_all(b"\n").map_err(storage)?;
        if self.0 - before > MAX_STAGED_ROW {
            return Err(super::super::staging::no_space());
        }
        if self.0 > budget {
            return Err(normalized_source_limit(self.0, budget));
        }
        Ok(())
    }
}
