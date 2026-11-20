use super::{AppError, CancellationToken, CaseId, ParquetStore, Run, RunReader, RunWriter};
use super::{MAX_SORT_FAN_IN, invalid_source};
use crate::parquet_store::partitioning::staging::MAX_STAGED_ROW;
use irmind_domain::{StableRecordKey, compare_record_keys};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};

// Two maximum-sized rows must always fit, even when wide merging cannot.
const HEAD_BYTES: u64 = 2 * MAX_STAGED_ROW + MAX_SORT_FAN_IN as u64;

pub(super) fn merge_group(
    store: &ParquetStore,
    case: &CaseId,
    mut runs: Vec<Run>,
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    while runs.len() > 1 {
        let mut input = VecDeque::from(runs);
        let mut output = Vec::new();
        while !input.is_empty() {
            let count = fitting_heads(&input);
            let group = input.drain(..count).collect::<Vec<_>>();
            let run = if group.len() == 1 {
                group.into_iter().next().ok_or_else(invalid_source)?
            } else {
                merge(store, case, &group, cancel)?
            };
            output.push(run);
        }
        runs = output;
    }
    runs.pop().ok_or_else(invalid_source)
}

fn fitting_heads(runs: &VecDeque<Run>) -> usize {
    let mut remaining = HEAD_BYTES;
    runs.iter()
        .take(MAX_SORT_FAN_IN)
        .take_while(|run| {
            let Some(after) = remaining.checked_sub(run.max_frame + 1) else {
                return false;
            };
            remaining = after;
            true
        })
        .count()
}

pub(super) fn merge(
    store: &ParquetStore,
    case: &CaseId,
    runs: &[Run],
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    if !(2..=MAX_SORT_FAN_IN).contains(&runs.len())
        || runs.iter().map(|run| run.max_frame + 1).sum::<u64>() > HEAD_BYTES
    {
        return Err(invalid_source());
    }
    let mut readers = runs
        .iter()
        .map(Run::reader)
        .collect::<Result<Vec<_>, _>>()?;
    let mut heap = BinaryHeap::with_capacity(runs.len());
    let mut has_offsets = None;
    for (index, reader) in readers.iter_mut().enumerate() {
        push_head(
            &mut heap,
            reader,
            index,
            Vec::new(),
            &mut has_offsets,
            cancel,
        )?;
    }
    let mut writer = RunWriter::new(store, case)?;
    while let Some(head) = heap.pop() {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        writer.push_encoded(&head.frame)?;
        push_head(
            &mut heap,
            &mut readers[head.index],
            head.index,
            head.frame,
            &mut has_offsets,
            cancel,
        )?;
    }
    // Each input reached EOF and authenticated its hash, total bytes and rows.
    let mut run = writer.finish()?;
    run.depth = runs.iter().map(|run| run.depth).max().unwrap_or(0) + 1;
    if let Some(profile) = &store.profile {
        profile.record_sort_run(run.bytes, runs.len() as u64, run.depth);
    }
    Ok(run)
}

fn push_head(
    heap: &mut BinaryHeap<Head>,
    reader: &mut RunReader,
    index: usize,
    frame: Vec<u8>,
    has_offsets: &mut Option<bool>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    if let Some((key, frame)) = reader.next_key(frame, cancel)? {
        // All runs belong to one source. Reject mixed provenance before the
        // fallible stable comparator is used by BinaryHeap's infallible Ord.
        let present = key.source_offset.is_some();
        if *has_offsets.get_or_insert(present) != present {
            return Err(invalid_source());
        }
        heap.push(Head { key, index, frame });
    }
    Ok(())
}

struct Head {
    key: StableRecordKey<'static>,
    index: usize,
    frame: Vec<u8>,
}

impl Ord for Head {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_record_keys(other.key, self.key, false)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.index.cmp(&self.index))
    }
}
impl PartialOrd for Head {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for Head {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Head {}
