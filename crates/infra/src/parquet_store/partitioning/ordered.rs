//! Speculative direct writing. Publication waits for the complete source hash.
mod producer;
use super::super::{
    AppError, CancellationToken, ParquetStore, PreparedSource, invalid_source, storage,
};
use super::Allocator;
use super::batch::{PreparedPartition, Writing};
use super::staging::Input;
use irmind_app::LocalBatchRequest;
pub(super) use producer::ParsedSource;
use producer::RowBatch;
use std::io::{Seek as _, SeekFrom};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

impl ParquetStore {
    pub(super) fn prepare_ordered_sources(
        &self,
        request: &LocalBatchRequest<'_>,
        inputs: Vec<Input>,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<Vec<PreparedSource>, AppError> {
        let prepared = std::thread::scope(|scope| {
            let workers = inputs
                .into_iter()
                .map(|input| {
                    // Each of at most four parsers can queue one bounded batch.
                    let (sender, receiver) = sync_channel(1);
                    let path = input.path.clone();
                    let restart = Arc::new(AtomicBool::new(false));
                    let worker_restart = Arc::clone(&restart);
                    let worker = scope.spawn(move || {
                        self.produce_ordered_rows(
                            input,
                            request.parser,
                            request.copy_original,
                            cancel,
                            &sender,
                            &worker_restart,
                        )
                    });
                    (receiver, worker, path, restart)
                })
                .collect::<Vec<_>>();
            let mut prepared = Ok(Vec::new());
            for (receiver, worker, path, restart) in workers {
                if prepared.is_err() {
                    // Unblock and join every producer before returning an error.
                    drop(receiver);
                    let _ = worker.join();
                    continue;
                }
                let mut trial = allocator.clone();
                let state = self
                    .consume_ordered_rows(request, &path, &receiver, &mut trial, cancel, &restart);
                drop(receiver);
                let parsed = worker.join().map_err(|_| invalid_source()).and_then(|v| v);
                let next = match (state, parsed) {
                    (Err(error), _) | (_, Err(error)) => Err(error),
                    (Ok(state), Ok(source)) => {
                        self.finish_ordered_source(request, source, state, trial, allocator, cancel)
                    }
                };
                match next {
                    Ok(source) => {
                        if let Ok(out) = &mut prepared {
                            out.push(source);
                        }
                    }
                    Err(error) => prepared = Err(error),
                }
            }
            prepared
        })?;
        // Preserve all-or-nothing parser preparation: no durable artifact is
        // published until every source has completed parsing and hash checks.
        prepared
            .into_iter()
            .map(|p| {
                let PreparedPartition {
                    source,
                    staged,
                    disk,
                } = p;
                drop(disk);
                let other_temporary_bytes = self.profile.as_ref().map_or(0, |p| {
                    p.staging_live.load(std::sync::atomic::Ordering::Relaxed)
                });
                self.publish_partition_source(
                    request,
                    source,
                    staged,
                    cancel,
                    other_temporary_bytes,
                )
            })
            .collect()
    }

    fn consume_ordered_rows(
        &self,
        request: &LocalBatchRequest<'_>,
        source_name: &str,
        receiver: &Receiver<RowBatch>,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
        restart: &AtomicBool,
    ) -> Result<Option<Writing>, AppError> {
        let _write = self
            .profile
            .as_ref()
            .map(|p| p.measure(super::super::PartitionPhase::Replay));
        let dir = self.case_dir(request.case_id)?;
        let parser = request.parser.identity_for_source(source_name)?;
        let mut writing = Writing::default();
        let mut previous = None;
        while let Ok(batch) = receiver.recv() {
            for row in batch.rows {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let key = row.sort_key();
                if let Some(old) = previous
                    && irmind_domain::compare_record_keys(old, key, false)
                        .map_err(|_| invalid_source())?
                        .is_gt()
                {
                    // Stop speculative parsing, then re-read and authenticate
                    // the complete source through the existing sort path.
                    restart.store(true, Ordering::Release);
                    return Ok(None);
                }
                previous = Some(key);
                writing.push_row(row, allocator, &dir, &batch.hash, parser)?;
            }
        }
        Ok(Some(writing))
    }

    fn finish_ordered_source(
        &self,
        request: &LocalBatchRequest<'_>,
        mut source: ParsedSource,
        state: Option<Writing>,
        trial: Allocator,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<PreparedPartition, AppError> {
        if let Some(mut state) = state {
            if source.report.is_none() {
                return Err(invalid_source());
            }
            let parser = request
                .parser
                .identity_for_source(&source.manifest.source)?;
            state.finish(
                &self.case_dir(request.case_id)?,
                &source.manifest.sha256,
                parser,
            )?;
            *allocator = trial;
            return PreparedPartition::new(source, state.staged, self.profile.clone());
        }
        source.source.seek(SeekFrom::Start(0)).map_err(storage)?;
        let expected = source.manifest.clone();
        let expected_sample = source.sample_hash;
        let input = Input {
            file: source.source,
            path: source.manifest.source,
            budget: source.budget,
        };
        let mut staged = if let Some(initial) = source.initial {
            self.stage_hashed_source(
                request.case_id,
                input,
                request.parser,
                request.copy_original,
                cancel,
                initial,
            )?
        } else {
            self.stage_source(
                request.case_id,
                input,
                request.parser,
                request.copy_original,
                cancel,
            )?
        };
        if staged.manifest != expected || staged.sample_hash != expected_sample {
            return Err(AppError::EvidenceMismatch(expected.sha256.as_str().into()));
        }
        {
            let _sort = self
                .profile
                .as_ref()
                .map(|p| p.measure(super::super::PartitionPhase::Sort));
            self.sort_staged_sources(request.case_id, std::slice::from_mut(&mut staged), cancel)?;
        }
        self.replay_partition_source(request, staged, allocator, cancel)
    }
}

#[cfg(test)]
mod tests;
