//! Canonical consumption of bounded parser queues into final writers.
use super::{
    Allocator, AppError, Arc, AtomicBool, CancellationToken, Duration, Input, ParquetStore,
    ParsedSource, ProducedSource, ProducerOutput, Receiver, RecvTimeoutError, RowBatch,
    invalid_source, scheduling, sync_channel,
};
use crate::parquet_store::writer::direct::DirectWriting;
use irmind_app::{MappedIngestRequest, MappedSourceAcquisition};

pub(in crate::parquet_store::partitioning) enum DirectChunk {
    Ordered(Vec<MappedSourceAcquisition>),
    NeedsSort {
        path: String,
        hash: irmind_domain::EvidenceHash,
        ordered: Vec<MappedSourceAcquisition>,
    },
}
impl ParquetStore {
    pub(in crate::parquet_store::partitioning) fn stream_direct_chunk(
        &self,
        request: &MappedIngestRequest<'_>,
        inputs: Vec<Input>,
        writing: &mut DirectWriting,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
    ) -> Result<DirectChunk, AppError> {
        let serial = self.direct_serial(request, &inputs)?;
        let operation = cancel.child_token();
        let batch = request;
        std::thread::scope(|scope| {
            let _abort = scheduling::Abort(operation.clone());
            let workers = inputs
                .into_iter()
                .map(|input| {
                    let (sender, receiver) = sync_channel(1);
                    let restart = Arc::new(AtomicBool::new(false));
                    let worker_restart = restart.clone();
                    let (start, permit) = scheduling::permit(serial);
                    let batch = &batch;
                    let operation = &operation;
                    let path = input.path.clone();
                    let logical = request.parser.logical_source(&path).to_owned();
                    let worker = scope.spawn(move || {
                        let result = self.produce_ordered_rows(
                            input,
                            batch,
                            operation,
                            ProducerOutput {
                                sender: &sender,
                                restart: &worker_restart,
                                start,
                            },
                        );
                        tag_source_error(result, path)
                    });
                    (receiver, worker, permit, logical)
                })
                .collect::<Vec<_>>();
            let mut result = Ok(DirectChunk::Ordered(Vec::new()));
            for (receiver, worker, permit, logical) in workers {
                if matches!(result, Ok(DirectChunk::Ordered(_))) {
                    let consumed = permit.release().and_then(|()| {
                        self.consume_direct(
                            request, &receiver, writing, allocator, &operation, &logical,
                        )
                    });
                    drop(receiver);
                    let parsed = worker.join().map_err(|_| invalid_source()).and_then(|v| v);
                    result = resolve_source(consumed, parsed, result);
                    if !matches!(result, Ok(DirectChunk::Ordered(_))) {
                        operation.cancel();
                    }
                } else {
                    drop(receiver);
                    if let Err(error) = worker.join().map_err(|_| invalid_source()).and_then(|v| v)
                    {
                        result = match result {
                            Err(current) => {
                                Err(super::super::attempt::prefer_failure(current, error))
                            }
                            other if matches!(error, AppError::Cancelled) => other,
                            _ => Err(error),
                        };
                    }
                }
            }
            result
        })
    }
    fn direct_serial(
        &self,
        request: &MappedIngestRequest<'_>,
        inputs: &[Input],
    ) -> Result<bool, AppError> {
        inputs.iter().try_fold(false, |serial, input| {
            Ok::<_, AppError>(
                serial
                    || self.source_parallelism(request.parser, &input.path)?
                        == irmind_app::SourceParallelism::Serial,
            )
        })
    }
    fn consume_direct(
        &self,
        request: &MappedIngestRequest<'_>,
        receiver: &Receiver<RowBatch>,
        writing: &mut DirectWriting,
        allocator: &mut Allocator,
        cancel: &CancellationToken,
        source: &str,
    ) -> Result<(), AppError> {
        let _replay = self
            .profile
            .as_ref()
            .map(|p| p.measure(super::super::super::PartitionPhase::Replay));
        let dir = self.case_dir(request.case_id)?;
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let started = std::time::Instant::now();
            let outcome = receiver.recv_timeout(Duration::from_millis(10));
            if let Some(profile) = &self.profile {
                profile.record_concurrency(
                    crate::parquet_store::profile::ConcurrencyPhase::ConsumerQueue,
                    started.elapsed(),
                );
            }
            match outcome {
                Ok(batch) => {
                    writing.register_source(&batch.hash, source)?;
                    for row in batch.rows {
                        writing.push(row, allocator, &dir, cancel)?;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }
}
fn resolve_source(
    consumed: Result<(), AppError>,
    parsed: Result<ProducedSource, AppError>,
    result: Result<DirectChunk, AppError>,
) -> Result<DirectChunk, AppError> {
    match (consumed, parsed, result) {
        (Err(error), _, _) if !matches!(error, AppError::Cancelled) => Err(error),
        (_, Err(error), _) | (Err(error), _, _) => Err(error),
        (
            Ok(()),
            Ok(ProducedSource::NeedsSort { path, hash }),
            Ok(DirectChunk::Ordered(ordered)),
        ) => Ok(DirectChunk::NeedsSort {
            path,
            hash,
            ordered,
        }),
        (Ok(()), Ok(ProducedSource::Ordered(source)), Ok(DirectChunk::Ordered(mut sources))) => {
            sources.push(ordered_acquisition(*source));
            Ok(DirectChunk::Ordered(sources))
        }
        _ => Err(invalid_source()),
    }
}

fn ordered_acquisition(source: ParsedSource) -> MappedSourceAcquisition {
    MappedSourceAcquisition {
        manifest: source.manifest,
        report: source.report,
        format_sample_sha256: source.sample_hash,
        decoded: source.mapping,
    }
}

fn tag_source_error(
    result: Result<ProducedSource, AppError>,
    path: String,
) -> Result<ProducedSource, AppError> {
    match result {
        Err(AppError::EvidenceMismatch(_)) => Err(AppError::SourceFailure(
            irmind_app::RejectedSource::try_new(
                path,
                irmind_app::SourceFailureReason::Hash,
                vec![],
            )?,
        )),
        other => other,
    }
}
