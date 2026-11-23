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
    Fallback(Input, Initial),
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
        return Ok(Choice::Fallback(input, initial));
    }
    let decoder = store
        .mapping_catalog
        .as_ref()
        .ok_or_else(invalid_source)?
        .decoder(id.name, id.version)
        .map_err(irmind_app::source_mapping::MappingError::into_app)?;
    let Some(ordering) = decoder.compact_ordering() else {
        return Ok(Choice::Fallback(input, initial));
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
    let mut batch = Vec::new();
    let mut pending = Vec::new();
    let mut count = 0_u64;
    let mut previous = None;
    let mut disordered = false;
    let mut too_large = false;
    let result = ordering.scan(
        SourceInput {
            metadata,
            reader: &mut reader,
        },
        &mut |locator| {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if locator.index != count
                || locator.frame_len == 0
                || locator
                    .frame_start
                    .checked_add(u64::from(locator.frame_len))
                    .is_none_or(|end| end > initial.2)
            {
                return Err(invalid_source());
            }
            count += 1;
            if count * (2 * runs::BYTES + ReorderedRecords::SLOT_BYTES) > input.budget {
                too_large = true;
                return Err(AppError::Cancelled);
            }
            let key = runs::key(locator);
            if let Some(old) = previous {
                disordered |= irmind_domain::compare_record_keys(old, key, false)
                    .map_err(|_| invalid_source())?
                    .is_gt();
            }
            previous = Some(key);
            batch.push(locator);
            if batch.len() == RUN_RECORDS {
                pending.push(write_run(store, request.case_id, &mut batch, cancel)?);
            }
            Ok(())
        },
    );
    if reader.io_failed {
        return Err(storage("compact Azure read"));
    }
    match result {
        Ok(false) => return Ok(Choice::Fallback(input, initial)),
        Err(AppError::Cancelled) if too_large && !cancel.is_cancelled() => {
            return Ok(Choice::Fallback(input, initial));
        }
        other => {
            other?;
        }
    }
    reader.drain(cancel)?;
    if reader.bytes != initial.2 || reader.finish() != initial.1 {
        return Err(AppError::EvidenceMismatch(irmind_app::hex(&initial.1)));
    }
    if !disordered {
        return Ok(Choice::Stream(input));
    }
    if !batch.is_empty() {
        pending.push(write_run(store, request.case_id, &mut batch, cancel)?);
    }
    Ok(Choice::Compact(Box::new(Planned {
        input,
        initial,
        runs: pending,
        count,
        sample_hash,
    })))
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
    let decoder = catalog
        .decoder(id.name, id.version)
        .map_err(irmind_app::source_mapping::MappingError::into_app)?;
    let ordering = decoder.compact_ordering().ok_or_else(invalid_source)?;
    let routes = mapped::projection_routes_for_direct(&catalog)?;
    let run = {
        let _sort = store
            .profile
            .as_ref()
            .map(|p| p.measure(PartitionPhase::Sort));
        runs::merge(store, request.case_id, runs, cancel)?
    };
    let receipts =
        store.create_private_object_spool(request.case_id, count * ReorderedRecords::SLOT_BYTES)?;
    let mut disk = super::super::temporary::DiskLease::new(store.profile.clone());
    disk.add(count * ReorderedRecords::SLOT_BYTES)?;
    let mut receipts = receipts;
    let mut account = ReorderedRecords::new(
        SourceRecordAccumulator::new(metadata, id, size, &catalog)?,
        count,
    )?;
    writing.register_source(&hash, logical)?;
    let root = store.case_dir(request.case_id)?;
    let mut normalized = CountBytes::default();
    let _replay = store
        .profile
        .as_ref()
        .map(|p| p.measure(PartitionPhase::Replay));
    {
        let mut decoder = ordering.replay(SourceFileInput {
            metadata,
            file: &mut input.file,
        });
        let mut reader = run.reader()?;
        while let Some(locator) = reader.next(cancel)? {
            let record = decoder.read(locator).map_err(|error| match error {
                AppError::EvidenceMismatch(_) => {
                    super::read::source_changed(input.path.clone()).unwrap_or_else(|error| error)
                }
                other => other,
            })?;
            let mapped = account.accept(record, receipts.as_file_mut())?;
            let row = mapped::project_row(&mapped, id, &hash, &routes)?;
            let key = row.sort_key();
            if key.record_index != locator.index
                || key.instant != Some(locator.time.instant())
                || key.source_offset.is_some()
            {
                return Err(invalid_source());
            }
            normalized.charge(&row, input.budget)?;
            writing.push(row, allocator, &root, cancel)?;
        }
    }
    let (current, live_size) = ParquetStore::hash_reader(&mut input.file, cancel)?;
    if current != digest || live_size != size {
        return Err(super::read::source_changed(input.path)?);
    }
    verify_source_unchanged(&input.file, &snapshot, &hash)?;
    let report = ParseReport {
        accepted: usize::try_from(count).map_err(storage)?,
        rejected: 0,
        samples: vec![],
    };
    let decoded = account.finish(receipts.as_file_mut(), &report)?;
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
        decoded,
    })
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
