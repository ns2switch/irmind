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
    while let Some(row) = reader.next(cancel)? {
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
        writer.push(&row)?;
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
        let head = reader.next(cancel)?;
        bytes = bytes.saturating_add(head.as_ref().map_or(0, RecordRow::estimated_bytes));
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
        let row = heads[index].take().ok_or_else(invalid_source)?;
        writer.push(&row)?;
        bytes = bytes.saturating_sub(row.estimated_bytes());
        drop(row);
        let next = readers[index].next(cancel)?;
        bytes = bytes.saturating_add(next.as_ref().map_or(0, RecordRow::estimated_bytes));
        if bytes > BATCH_BYTES {
            return Ok(None);
        }
        heads[index] = next;
    }
    // Every reader reached EOF and verified its row count, byte count and hash.
    Ok(Some(writer.finish()?))
}

fn smallest_head(heads: &[Option<RecordRow>]) -> Result<Option<usize>, AppError> {
    let mut best: Option<usize> = None;
    for (index, row) in heads.iter().enumerate() {
        let Some(row) = row else {
            continue;
        };
        if let Some(old) = best {
            let old = heads[old].as_ref().ok_or_else(invalid_source)?;
            // Equal keys retain their original run order, as in the stable
            // external merge. Use the shared fallible comparator throughout.
            if compare(row, old)? != Ordering::Less {
                continue;
            }
        }
        best = Some(index);
    }
    Ok(best)
}
