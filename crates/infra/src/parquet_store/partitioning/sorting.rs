//! External stable ordering for parsers whose completed groups arrive out of
//! source order. Ordered sources avoid this pass entirely.
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

impl ParquetStore {
    pub(super) fn sort_staged_sources(
        &self,
        case: &CaseId,
        staged: &mut [StagedSource],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let max_bytes = staged
            .iter()
            .filter(|s| s.needs_sort)
            .map(|s| {
                s.spool
                    .as_file()
                    .metadata()
                    .map(|m| m.len())
                    .map_err(storage)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max();
        if let Some(bytes) = max_bytes {
            let required = bytes
                .checked_mul(2)
                .and_then(|n| n.checked_add(64 * 1024 * 1024))
                .ok_or_else(invalid_source)?;
            super::staging::check_space(
                fs4::available_space(self.spool_dir(case)?).map_err(storage)?,
                required,
            )?;
        }
        // One external sort at a time, after the parallel parser stage.
        for source in staged.iter_mut().filter(|s| s.needs_sort) {
            sort_source(self, case, source, cancel)?;
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
    writer.finish()
}
fn merge(
    store: &ParquetStore,
    case: &CaseId,
    left: &Run,
    right: &Run,
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    let (mut a, mut b) = (left.reader()?, right.reader()?);
    let (mut ah, mut bh) = (a.next(cancel)?, b.next(cancel)?);
    let mut writer = RunWriter::new(store, case)?;
    while ah.is_some() || bh.is_some() {
        let take_a = match (&ah, &bh) {
            (Some(a), Some(b)) => compare(a, b)? != Ordering::Greater,
            (Some(_), None) => true,
            _ => false,
        };
        if take_a {
            writer.push(ah.as_ref().ok_or_else(invalid_source)?)?;
            ah = a.next(cancel)?;
        } else {
            writer.push(bh.as_ref().ok_or_else(invalid_source)?)?;
            bh = b.next(cancel)?;
        }
    }
    writer.finish()
}
fn add_run(
    store: &ParquetStore,
    case: &CaseId,
    levels: &mut Vec<Option<Run>>,
    mut run: Run,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let mut level = 0;
    loop {
        if level >= 64 {
            return Err(invalid_source());
        }
        if level == levels.len() {
            levels.push(None);
        }
        let Some(old) = levels[level].take() else {
            levels[level] = Some(run);
            return Ok(());
        };
        run = merge(store, case, &old, &run, cancel)?;
        level += 1;
    }
}
fn sort_source(
    store: &ParquetStore,
    case: &CaseId,
    source: &mut StagedSource,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
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
    levels: Vec<Option<Run>>,
    cancel: &CancellationToken,
) -> Result<Run, AppError> {
    let mut final_run = None;
    for run in levels.into_iter().rev().flatten() {
        final_run = Some(if let Some(old) = final_run {
            merge(store, case, &old, &run, cancel)?
        } else {
            run
        });
    }
    final_run.ok_or_else(invalid_source)
}

#[cfg(test)]
mod tests;
