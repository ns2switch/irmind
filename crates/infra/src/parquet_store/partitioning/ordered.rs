//! Speculative direct writing. Publication waits for the complete source hash.
mod direct;
mod producer;
pub(in crate::parquet_store::partitioning) use direct::DirectChunk;
mod scheduling;
use super::super::{AppError, CancellationToken, ParquetStore, PreparedSource, invalid_source};
use super::Allocator;
use super::batch::{PreparedPartition, Writing};
use super::staging::Input;
use irmind_app::LocalBatchRequest;
pub(super) use producer::ParsedSource;
use producer::{ProducedSource, RowBatch};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

impl ParquetStore {
    fn source_parallelism(
        &self,
        parser: &dyn irmind_app::StreamingEventParser,
        source: &str,
    ) -> Result<irmind_app::SourceParallelism, AppError> {
        let id = parser.identity_for_source(source)?;
        if let Some(catalog) = &self.mapping_catalog
            && catalog.supports_decoder(id.name, id.version)
        {
            Ok(catalog
                .decoder(id.name, id.version)
                .map_err(irmind_app::source_mapping::MappingError::into_app)?
                .source_parallelism())
        } else {
            parser.source_parallelism(source)
        }
    }

    pub(super) fn prepare_ordered_sources(
        &self,
        request: &LocalBatchRequest<'_>,
        inputs: Vec<Input>,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<Vec<PreparedSource>, AppError> {
        let serial = inputs.iter().try_fold(false, |serial, input| {
            let capability = self.source_parallelism(request.parser, &input.path)?;
            Ok::<_, AppError>(serial || capability == irmind_app::SourceParallelism::Serial)
        })?;
        let operation = cancel.child_token();
        let cancel = &operation;
        let prepared = std::thread::scope(|scope| {
            let mut abort = scheduling::Abort(operation.clone());
            let workers = inputs
                .into_iter()
                .map(|input| {
                    // Each of at most four parsers can queue one bounded batch.
                    let (sender, receiver) = sync_channel(1);
                    let path = input.path.clone();
                    let restart = Arc::new(AtomicBool::new(false));
                    let worker_restart = Arc::clone(&restart);
                    let (start, permit) = scheduling::permit(serial);
                    let worker = scope.spawn(move || {
                        let mut abort = scheduling::Abort(cancel.clone());
                        let result = self.produce_ordered_rows(
                            input,
                            request,
                            cancel,
                            &sender,
                            &worker_restart,
                            start,
                        );
                        if result.is_ok() {
                            abort.0 = CancellationToken::new();
                        }
                        result
                    });
                    (receiver, worker, path, restart, permit)
                })
                .collect::<Vec<_>>();
            let mut prepared = Ok(Vec::new());
            for (receiver, worker, path, restart, permit) in workers {
                if prepared.is_err() {
                    // Unblock and join every producer before returning an error.
                    drop(receiver);
                    if let Ok(Err(error)) = worker.join()
                        && matches!(prepared, Err(AppError::Cancelled))
                    {
                        prepared = Err(error);
                    }
                    continue;
                }
                let mut trial = allocator.clone();
                let state = permit.release().and_then(|()| {
                    self.consume_ordered_rows(
                        request, &path, &receiver, &mut trial, cancel, &restart,
                    )
                });
                drop(receiver);
                let parsed = worker.join().map_err(|_| invalid_source()).and_then(|v| v);
                let next = match (state, parsed) {
                    (_, Err(error)) | (Err(error), _) => Err(error),
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
                    Err(error) => {
                        cancel.cancel();
                        prepared = Err(error);
                    }
                }
            }
            if prepared.is_ok() {
                abort.0 = CancellationToken::new();
            }
            prepared
        })?;
        self.publish_prepared_sources(request, prepared, cancel)
    }

    fn publish_prepared_sources(
        &self,
        request: &LocalBatchRequest<'_>,
        prepared: Vec<PreparedPartition>,
        cancel: &CancellationToken,
    ) -> Result<Vec<PreparedSource>, AppError> {
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
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let batch = match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(batch) => batch,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            };
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
        source: ProducedSource,
        state: Option<Writing>,
        trial: Allocator,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<PreparedPartition, AppError> {
        if let ProducedSource::Ordered(source) = source {
            let mut state = state.ok_or_else(invalid_source)?;
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
        // The parser worker prepares a complete authenticated fallback while
        // the other source workers continue in parallel.
        drop(state);
        let ProducedSource::Disordered(mut staged) = source else {
            return Err(invalid_source());
        };
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
