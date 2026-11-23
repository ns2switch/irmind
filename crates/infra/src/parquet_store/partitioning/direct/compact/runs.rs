use super::{AppError, CancellationToken, ParquetStore, invalid_source, storage};
use crate::parquet_store::partitioning::{sorting::MAX_SORT_FAN_IN, temporary::DiskLease};
use irmind_app::source_mapping::CompactRecordLocator;
use irmind_domain::{CaseId, IndexedInstant, IndexedTime, StableRecordKey, TimePrecision};
use sha2::{Digest, Sha256};
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
};

pub(super) const BYTES: u64 = 68;
const WIDTH: usize = 68;

pub(super) fn key(locator: CompactRecordLocator) -> StableRecordKey<'static> {
    StableRecordKey {
        instant: Some(locator.time.instant()),
        source: "",
        source_hash: "",
        source_offset: None,
        record_index: locator.index,
    }
}
fn encode(locator: CompactRecordLocator) -> [u8; WIDTH] {
    let mut bytes = [0; WIDTH];
    bytes[..8].copy_from_slice(&locator.time.instant().unix_micros().to_be_bytes());
    bytes[8..10].copy_from_slice(&locator.time.instant().submicro_nanos().to_be_bytes());
    bytes[10] = locator.time.precision().code();
    bytes[11] = u8::from(locator.time.inferred());
    bytes[12..20].copy_from_slice(&locator.index.to_be_bytes());
    bytes[20..28].copy_from_slice(&locator.frame_start.to_be_bytes());
    bytes[28..32].copy_from_slice(&locator.frame_len.to_be_bytes());
    bytes[32..64].copy_from_slice(&locator.frame_hash);
    bytes[64..].copy_from_slice(&locator.tuple.to_be_bytes());
    bytes
}

fn decode(bytes: [u8; WIDTH]) -> Result<CompactRecordLocator, AppError> {
    let micros = i64::from_be_bytes(bytes[..8].try_into().map_err(|_| invalid_source())?);
    let nanos = u16::from_be_bytes(bytes[8..10].try_into().map_err(|_| invalid_source())?);
    let instant = IndexedInstant::new(micros, nanos).map_err(|_| invalid_source())?;
    let precision = TimePrecision::from_code(bytes[10]).map_err(|_| invalid_source())?;
    let inferred = match bytes[11] {
        0 => false,
        1 => true,
        _ => return Err(invalid_source()),
    };
    Ok(CompactRecordLocator {
        time: IndexedTime::new(instant, precision, inferred).map_err(|_| invalid_source())?,
        index: u64::from_be_bytes(bytes[12..20].try_into().map_err(|_| invalid_source())?),
        frame_start: u64::from_be_bytes(bytes[20..28].try_into().map_err(|_| invalid_source())?),
        frame_len: u32::from_be_bytes(bytes[28..32].try_into().map_err(|_| invalid_source())?),
        frame_hash: bytes[32..64].try_into().map_err(|_| invalid_source())?,
        tuple: u32::from_be_bytes(bytes[64..].try_into().map_err(|_| invalid_source())?),
    })
}

pub(super) struct Run {
    path: tempfile::TempPath,
    total: u64,
    sha256: [u8; 32],
    depth: u64,
    _disk: DiskLease,
}

pub(super) struct Writer {
    output: BufWriter<tempfile::NamedTempFile>,
    count: u64,
    digest: Sha256,
    disk: DiskLease,
}
impl Writer {
    pub(super) fn new(store: &ParquetStore, case: &CaseId) -> Result<Self, AppError> {
        Ok(Self {
            output: BufWriter::with_capacity(64 * 1024, store.create_normalized_spool(case)?),
            count: 0,
            digest: Sha256::new(),
            disk: DiskLease::new(store.profile.clone()),
        })
    }
    pub(super) fn push(&mut self, record: CompactRecordLocator) -> Result<(), AppError> {
        let bytes = encode(record);
        self.output.write_all(&bytes).map_err(storage)?;
        self.digest.update(bytes);
        self.count += 1;
        self.disk.add(BYTES)
    }
    pub(super) fn finish(
        self,
        store: &ParquetStore,
        depth: u64,
        fan_in: u64,
    ) -> Result<Run, AppError> {
        let path = self.output.into_inner().map_err(storage)?.into_temp_path();
        if let Some(profile) = &store.profile {
            profile.record_sort_run(self.count * BYTES, fan_in, depth);
        }
        Ok(Run {
            path,
            total: self.count,
            sha256: self.digest.finalize().into(),
            depth,
            _disk: self.disk,
        })
    }
}

pub(super) struct Reader<'a> {
    input: BufReader<File>,
    run: &'a Run,
    left: u64,
    digest: Sha256,
    previous: Option<(IndexedInstant, u64)>,
}

impl Run {
    pub(super) fn reader(&self) -> Result<Reader<'_>, AppError> {
        let path: &std::path::Path = self.path.as_ref();
        let parent = path.parent().ok_or_else(invalid_source)?;
        let name = path.file_name().ok_or_else(invalid_source)?;
        let file = irmind_fs::open_regular_no_follow(parent, std::path::Path::new(name))
            .map_err(storage)?;
        if file.metadata().map_err(storage)?.len() != self.total * BYTES {
            return Err(invalid_source());
        }
        Ok(Reader {
            input: BufReader::with_capacity(16 * 1024, file),
            run: self,
            left: self.total,
            digest: Sha256::new(),
            previous: None,
        })
    }
}

impl Reader<'_> {
    pub(super) fn next(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<CompactRecordLocator>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if self.left == 0 {
            let actual: [u8; 32] = self.digest.clone().finalize().into();
            if actual != self.run.sha256 || self.input.read(&mut [0]).map_err(storage)? != 0 {
                return Err(invalid_source());
            }
            return Ok(None);
        }
        let mut raw = [0; WIDTH];
        self.input.read_exact(&mut raw).map_err(storage)?;
        self.digest.update(raw);
        self.left -= 1;
        let locator = decode(raw)?;
        let current = order(locator);
        if self.previous.is_some_and(|previous| previous >= current) {
            return Err(invalid_source());
        }
        self.previous = Some(current);
        Ok(Some(locator))
    }
}

pub(super) fn order(locator: CompactRecordLocator) -> (IndexedInstant, u64) {
    // The common stable key for one source with no signed offsets.
    (locator.time.instant(), locator.index)
}

pub(super) fn merge(
    store: &ParquetStore,
    case: &CaseId,
    mut group: Vec<Run>,
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    while group.len() > 1 {
        let mut pending = group.into_iter();
        let mut output = Vec::new();
        loop {
            let batch: Vec<_> = pending.by_ref().take(MAX_SORT_FAN_IN).collect();
            match batch.len() {
                0 => break,
                1 => output.extend(batch),
                _ => output.push(merge_batch(store, case, &batch, cancel)?),
            }
        }
        group = output;
    }
    group.pop().ok_or_else(invalid_source)
}

fn merge_batch(
    store: &ParquetStore,
    case: &CaseId,
    batch: &[Run],
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    let mut readers = batch
        .iter()
        .map(Run::reader)
        .collect::<Result<Vec<_>, _>>()?;
    let mut heads = vec![None; readers.len()];
    let mut heap = BinaryHeap::with_capacity(readers.len());
    let mut push =
        |index: usize, heap: &mut BinaryHeap<_>, heads: &mut [Option<_>]| -> Result<(), AppError> {
            if let Some(locator) = readers[index].next(cancel)? {
                heads[index] = Some(locator);
                heap.push(Reverse((order(locator), index)));
            }
            Ok(())
        };
    let mut out = Writer::new(store, case)?;
    for index in 0..heads.len() {
        push(index, &mut heap, &mut heads)?;
    }
    while let Some(Reverse((_, index))) = heap.pop() {
        out.push(heads[index].take().ok_or_else(invalid_source)?)?;
        push(index, &mut heap, &mut heads)?;
    }
    out.finish(
        store,
        batch.iter().map(|run| run.depth).max().unwrap_or(0) + 1,
        batch.len() as u64,
    )
}
