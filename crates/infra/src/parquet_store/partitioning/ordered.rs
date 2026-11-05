//! Speculative direct writing. Publication waits for the complete source hash.
mod producer;
use super::super::{
    AppError, CancellationToken, ParquetStore, PreparedSource, invalid_source, storage,
};
use super::Allocator;
use super::batch::Writing;
use super::staging::Input;
use irmind_app::LocalBatchRequest;
pub(super) use producer::ParsedSource;
use producer::RowBatch;
use std::io::{Seek as _, SeekFrom};
use std::sync::mpsc::{Receiver, sync_channel};

impl ParquetStore {
    pub(super) fn prepare_ordered_sources(
        &self,
        request: &LocalBatchRequest<'_>,
        inputs: Vec<Input>,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<Vec<PreparedSource>, AppError> {
        std::thread::scope(|scope| {
            let workers = inputs
                .into_iter()
                .map(|input| {
                    // Each of at most four parsers can queue one bounded batch.
                    let (sender, receiver) = sync_channel(1);
                    let path = input.path.clone();
                    let worker = scope.spawn(move || {
                        self.produce_ordered_rows(
                            input,
                            request.parser,
                            request.copy_original,
                            cancel,
                            &sender,
                        )
                    });
                    (receiver, worker, path)
                })
                .collect::<Vec<_>>();
            let mut prepared = Ok(Vec::new());
            for (receiver, worker, path) in workers {
                if prepared.is_err() {
                    // Unblock and join every producer before returning an error.
                    drop(receiver);
                    let _ = worker.join();
                    continue;
                }
                let mut trial = allocator.clone();
                let state =
                    self.consume_ordered_rows(request, &path, &receiver, &mut trial, cancel);
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
        })
    }

    fn consume_ordered_rows(
        &self,
        request: &LocalBatchRequest<'_>,
        source_name: &str,
        receiver: &Receiver<RowBatch>,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<Option<Writing>, AppError> {
        let _write = self
            .profile
            .as_ref()
            .map(|p| p.measure(super::super::PartitionPhase::Replay));
        let dir = self.case_dir(request.case_id)?;
        let parser = request.parser.identity_for_source(source_name)?;
        let mut writing = Some(Writing::default());
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
                    // Drop all provisional Parquet sinks and segments now.
                    writing = None;
                }
                previous = Some(key);
                if let Some(state) = &mut writing {
                    state.push_row(row, allocator, &dir, &batch.hash, parser)?;
                }
            }
        }
        Ok(writing)
    }

    fn finish_ordered_source(
        &self,
        request: &LocalBatchRequest<'_>,
        mut source: ParsedSource,
        state: Option<Writing>,
        trial: Allocator,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<PreparedSource, AppError> {
        if let Some(mut state) = state {
            let parser = request
                .parser
                .identity_for_source(&source.manifest.source)?;
            state.finish(
                &self.case_dir(request.case_id)?,
                &source.manifest.sha256,
                parser,
            )?;
            let prepared =
                self.publish_partition_source(request, source, state.staged, cancel, 0)?;
            *allocator = trial;
            return Ok(prepared);
        }
        source.source.seek(SeekFrom::Start(0)).map_err(storage)?;
        let expected = source.manifest.clone();
        let expected_sample = source.sample_hash;
        let input = Input {
            file: source.source,
            path: source.manifest.source,
            budget: source.budget,
        };
        let mut staged = self.stage_source(
            request.case_id,
            input,
            request.parser,
            request.copy_original,
            cancel,
        )?;
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
        let bytes = staged.spool.as_file().metadata().map_err(storage)?.len();
        self.write_partition_source(request, staged, allocator, cancel, bytes)
    }
}

#[cfg(test)]
mod tests;
