//! External stable ordering for parsers whose completed groups arrive out of
//! source order. Ordered sources avoid this pass entirely.
mod heap_merge;
mod natural;
mod run;
use super::super::{
    AppError, BATCH_BYTES, BATCH_ROWS, CancellationToken, CaseId, ParquetStore, RecordRow,
    invalid_source, storage,
};
use super::staging::StagedSource;
use run::{Run, RunReader, RunWriter};
use std::cmp::Ordering;
use std::io::{Seek as _, SeekFrom};

// Bound the number of open run files and heap heads per merge.
const MAX_SORT_FAN_IN: usize = 64;
const SORT_GROUP_READERS: usize = 128;
// Input runs and their in-progress replacement each occupy at most the
// normalized spool size. The spool itself is reserved separately.
pub(super) const SORT_SCRATCH_COPIES: u64 = 2;

pub(super) fn sort_workers(workers: usize) -> usize {
    workers.min(SORT_GROUP_READERS / MAX_SORT_FAN_IN)
}

impl ParquetStore {
    pub(super) fn sort_staged_sources(
        &self,
        case: &CaseId,
        staged: &mut [StagedSource],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let mut sources = staged
            .iter_mut()
            .filter(|source| source.needs_sort)
            .collect::<Vec<_>>();
        // At most two wide merges run at once. On a seven-worker machine
        // this still leaves room for the case and Parquet file descriptors.
        let workers = sort_workers(self.workers.count());
        for group in sources.chunks_mut(workers) {
            let required = group
                .iter()
                .try_fold(64_u64 * 1024 * 1024, |bytes, source| {
                    let size = source.spool.as_file().metadata().map_err(storage)?.len();
                    size.checked_mul(SORT_SCRATCH_COPIES)
                        .and_then(|size| bytes.checked_add(size))
                        .ok_or_else(invalid_source)
                })?;
            super::staging::check_space(
                fs4::available_space(self.spool_dir(case)?).map_err(storage)?,
                required,
            )?;
            let operation = cancel.child_token();
            std::thread::scope(|scope| {
                let jobs = group
                    .iter_mut()
                    .map(|source| {
                        let operation = &operation;
                        scope.spawn(move || {
                            let result = sort_source(self, case, source, operation);
                            if result.is_err() {
                                operation.cancel();
                            }
                            result
                        })
                    })
                    .collect::<Vec<_>>();
                let mut failure = None;
                for job in jobs {
                    let result = job
                        .join()
                        .map_err(|_| invalid_source())
                        .and_then(|result| result);
                    if let Err(error) = result {
                        operation.cancel();
                        failure = Some(match failure {
                            None => error,
                            Some(previous) => super::attempt::prefer_failure(previous, error),
                        });
                    }
                }
                match failure {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            })?;
        }
        Ok(())
    }
}
fn compare(a: &RecordRow, b: &RecordRow) -> Result<Ordering, AppError> {
    irmind_domain::compare_record_keys(a.sort_key(), b.sort_key(), false)
        .map_err(|_| invalid_source())
}
fn sorted_run(
    store: &ParquetStore,
    case: &CaseId,
    mut rows: Vec<RecordRow>,
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    let mut failed = false;
    rows.sort_by(|a, b| {
        compare(a, b).unwrap_or_else(|_| {
            failed = true;
            Ordering::Equal
        })
    });
    if failed {
        return Err(invalid_source());
    }
    let mut writer = RunWriter::new(store, case)?;
    for row in rows {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        writer.push(&row)?;
    }
    let run = writer.finish()?;
    if let Some(profile) = &store.profile {
        profile.record_sort_run(run.bytes, 0, 0);
    }
    Ok(run)
}
fn add_run(
    store: &ParquetStore,
    case: &CaseId,
    levels: &mut Vec<Vec<Run>>,
    mut run: Run,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    for level in 0..64 {
        if level == levels.len() {
            levels.push(Vec::new());
        }
        let pending = &mut levels[level];
        pending.push(run);
        if pending.len() < MAX_SORT_FAN_IN {
            return Ok(());
        }
        run = heap_merge::merge_group(store, case, std::mem::take(pending), cancel)?;
    }
    Err(invalid_source())
}
fn sort_source(
    store: &ParquetStore,
    case: &CaseId,
    source: &mut StagedSource,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let _sort = store
        .profile
        .as_ref()
        .map(|p| p.measure(super::super::PartitionPhase::Sort));
    let final_run = match natural::try_sort(store, case, source, cancel)? {
        Some(run) => run,
        None => external_sort(store, case, source, cancel)?,
    };
    source.normalized_hash = run::copy_final(
        &final_run,
        source.spool.as_file_mut(),
        &mut source.disk,
        cancel,
    )?;
    if let Some(profile) = &store.profile {
        profile.record_sort_copy(final_run.bytes);
    }
    source
        .spool
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(storage)?;
    source.needs_sort = false;
    Ok(())
}

fn staged_reader(source: &mut StagedSource) -> Result<RunReader, AppError> {
    source
        .spool
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(storage)?;
    let size = source.spool.as_file().metadata().map_err(storage)?.len();
    Ok(RunReader::new(
        source.spool.as_file().try_clone().map_err(storage)?,
        source.normalized_hash,
        size,
        source.report.accepted,
    ))
}

fn external_sort(
    store: &ParquetStore,
    case: &CaseId,
    source: &mut StagedSource,
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    let mut reader = staged_reader(source)?;
    let mut levels = Vec::new();
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = reader.next(cancel)? {
        bytes = bytes.saturating_add(row.estimated_bytes());
        rows.push(row);
        if bytes >= BATCH_BYTES || rows.len() >= BATCH_ROWS {
            add_run(
                store,
                case,
                &mut levels,
                sorted_run(store, case, std::mem::take(&mut rows), cancel)?,
                cancel,
            )?;
            bytes = 0;
        }
    }
    drop(reader);
    if !rows.is_empty() {
        add_run(
            store,
            case,
            &mut levels,
            sorted_run(store, case, rows, cancel)?,
            cancel,
        )?;
    }
    finish_runs(store, case, levels, cancel)
}

fn finish_runs(
    store: &ParquetStore,
    case: &CaseId,
    levels: Vec<Vec<Run>>,
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    let mut final_run = None;
    for mut runs in levels {
        // Lower levels contain the most recent input. The carry must follow
        // the older runs within this level so equal keys remain stable.
        runs.extend(final_run.take());
        if !runs.is_empty() {
            final_run = Some(heap_merge::merge_group(store, case, runs, cancel)?);
        }
    }
    final_run.ok_or_else(invalid_source)
}

#[cfg(test)]
mod tests;
