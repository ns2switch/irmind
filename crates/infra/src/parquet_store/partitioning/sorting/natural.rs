//! Merge a bounded number of existing monotonic runs before using chunk sorting.
use super::super::super::{
    AppError, BATCH_BYTES, CancellationToken, CaseId, ParquetStore, RecordRow, invalid_source,
};
use super::{Run, RunWriter, StagedSource, compare};
use std::cmp::Ordering;

const MAX_RUNS: usize = 32;

pub(super) fn try_sort(
    store: &ParquetStore,
    case: &CaseId,
    source: &mut StagedSource,
    cancel: &CancellationToken,
) -> Result<Option<Run>, AppError> {
    let Some(runs) = split_runs(store, case, source, cancel)? else {
        return Ok(None);
    };
    merge_runs(store, case, &runs, cancel)
}

fn split_runs(
    store: &ParquetStore,
    case: &CaseId,
    source: &mut StagedSource,
    cancel: &CancellationToken,
) -> Result<Option<Vec<Run>>, AppError> {
    let mut reader = super::staged_reader(source)?;
    let mut writer = RunWriter::new(store, case)?;
    let mut runs = Vec::new();
    let mut previous = None;
    while let Some((row, encoded)) = reader.next_encoded(cancel)? {
        let key = row.sort_key();
        if let Some(old) = previous
            && irmind_domain::compare_record_keys(old, key, false)
                .map_err(|_| invalid_source())?
                .is_gt()
        {
            // Do not retain an unbounded number of descriptors or open files.
            if runs.len() + 1 == MAX_RUNS {
                return Ok(None);
            }
            runs.push(writer.finish()?);
            writer = RunWriter::new(store, case)?;
        }
        writer.push_encoded(&encoded)?;
        previous = Some(key);
    }
    runs.push(writer.finish()?);
    Ok(Some(runs))
}

fn merge_runs(
    store: &ParquetStore,
    case: &CaseId,
    runs: &[Run],
    cancel: &CancellationToken,
) -> Result<Option<Run>, AppError> {
    let mut readers = runs
        .iter()
        .map(Run::reader)
        .collect::<Result<Vec<_>, _>>()?;
    let mut heads = Vec::new();
    let mut bytes = 0usize;
    for reader in &mut readers {
        let head = reader.next_encoded(cancel)?;
        bytes = bytes.saturating_add(head_bytes(head.as_ref()));
        if bytes > BATCH_BYTES {
            return Ok(None);
        }
        heads.push(head);
    }
    let mut writer = RunWriter::new(store, case)?;
    while let Some(index) = smallest_head(&heads)? {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let head = heads[index].take().ok_or_else(invalid_source)?;
        writer.push_encoded(&head.1)?;
        bytes = bytes.saturating_sub(head.0.estimated_bytes().saturating_add(head.1.capacity()));
        drop(head);
        let next = readers[index].next_encoded(cancel)?;
        bytes = bytes.saturating_add(head_bytes(next.as_ref()));
        if bytes > BATCH_BYTES {
            return Ok(None);
        }
        heads[index] = next;
    }
    // Every reader reached EOF and verified its row count, byte count and hash.
    Ok(Some(writer.finish()?))
}

fn smallest_head(heads: &[Option<(RecordRow, Vec<u8>)>]) -> Result<Option<usize>, AppError> {
    let mut best: Option<usize> = None;
    for (index, row) in heads.iter().enumerate() {
        let Some(row) = row else {
            continue;
        };
        if let Some(old) = best {
            let old = heads[old].as_ref().ok_or_else(invalid_source)?;
            // Equal keys retain their original run order, as in the stable
            // external merge. Use the shared fallible comparator throughout.
            if compare(&row.0, &old.0)? != Ordering::Less {
                continue;
            }
        }
        best = Some(index);
    }
    Ok(best)
}

fn head_bytes(row: Option<&(RecordRow, Vec<u8>)>) -> usize {
    row.map_or(0, |(row, encoded)| {
        row.estimated_bytes().saturating_add(encoded.capacity())
    })
}
