//! Canonical consumption of bounded parser queues into final writers.
use super::{
    Allocator, AppError, Arc, AtomicBool, CancellationToken, Duration, Input, LocalBatchRequest,
    ParquetStore, ParsedSource, ProducedSource, Receiver, RecvTimeoutError, RowBatch,
    invalid_source, scheduling, sync_channel,
};
use crate::parquet_store::writer::direct::DirectWriting;
use irmind_app::{MappedIngestRequest, MappedSourceAcquisition};

pub(in crate::parquet_store::partitioning) enum DirectChunk {
    Ordered(Vec<MappedSourceAcquisition>),
    NeedsSort,
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
        let batch = producer_request(request);
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
                            &sender,
                            &worker_restart,
                            start,
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
                    result = match (consumed, parsed, result) {
                        (Err(error), _, _) if !matches!(error, AppError::Cancelled) => Err(error),
                        (_, Err(error), _) | (Err(error), _, _) => Err(error),
                        (Ok(()), Ok(ProducedSource::Disordered(_)), _) => {
                            Ok(DirectChunk::NeedsSort)
                        }
                        (
                            Ok(()),
                            Ok(ProducedSource::Ordered(source)),
                            Ok(DirectChunk::Ordered(mut sources)),
                        ) => {
                            sources.push(ordered_acquisition(source)?);
                            Ok(DirectChunk::Ordered(sources))
                        }
                        _ => Err(invalid_source()),
                    };
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
            match receiver.recv_timeout(Duration::from_millis(10)) {
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
fn ordered_acquisition(mut source: ParsedSource) -> Result<MappedSourceAcquisition, AppError> {
    Ok(MappedSourceAcquisition {
        manifest: source.manifest,
        report: source.report.take().ok_or_else(invalid_source)?,
        format_sample_sha256: source.sample_hash,
        decoded: source.mapping.take().ok_or_else(invalid_source)?,
    })
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

fn producer_request<'a>(request: &MappedIngestRequest<'a>) -> LocalBatchRequest<'a> {
    LocalBatchRequest {
        case_id: request.case_id,
        source_root: request.source_root,
        relative_paths: request.relative_paths,
        copy_original: request.copy_original,
        parser: request.parser,
        // Only the coordinator allocates partitions from the validated inventory.
        committed_artifacts: &[],
        limits: request.limits,
    }
}
