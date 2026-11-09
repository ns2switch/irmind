use super::super::staging::{Input, MAX_STAGED_ROW, StagedSource};
use super::{AppError, CancellationToken, MappedIngestRequest, ParquetStore, invalid_source};
use crate::parquet_store::writer::direct::DirectWriting;
use crate::parquet_store::{RecordRow, storage};
use std::io::{BufRead, Read as _, Seek as _};

pub(super) fn stage(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    inputs: Vec<Input>,
    cancel: &CancellationToken,
) -> Result<Vec<StagedSource>, AppError> {
    // The source scheduler keeps serial-only decoders in canonical order.
    let serial = inputs.iter().try_fold(false, |old, input| {
        let id = request.parser.identity_for_source(&input.path)?;
        let decoder = store
            .mapping_catalog
            .as_ref()
            .ok_or_else(invalid_source)?
            .decoder(id.name, id.version)
            .map_err(irmind_app::source_mapping::MappingError::into_app)?;
        Ok::<_, AppError>(
            old || decoder.source_parallelism() == irmind_app::SourceParallelism::Serial,
        )
    })?;
    if serial {
        let hashed = std::thread::scope(|scope| {
            let handles = inputs
                .into_iter()
                .map(|mut input| {
                    scope.spawn(move || {
                        let initial = crate::parquet_store::local::stream::initial_hash(
                            &mut input.file,
                            cancel,
                            store.profile.as_deref(),
                        )?;
                        Ok::<_, AppError>((input, initial))
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|h| h.join().map_err(|_| invalid_source())?)
                .collect::<Result<Vec<_>, AppError>>()
        })?;
        return hashed
            .into_iter()
            .map(|(input, initial)| {
                let path = input.path.clone();
                hash_failure(
                    store.stage_hashed_source(
                        request.case_id,
                        input,
                        request.parser,
                        request.copy_original,
                        cancel,
                        initial,
                    ),
                    path,
                )
            })
            .collect();
    }
    parallel_stage(store, request, inputs, cancel)
}
fn parallel_stage(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    inputs: Vec<Input>,
    cancel: &CancellationToken,
) -> Result<Vec<StagedSource>, AppError> {
    let operation = cancel.child_token();
    std::thread::scope(|scope| {
        let handles = inputs
            .into_iter()
            .map(|input| {
                let operation = &operation;
                scope.spawn(move || stage_one(store, request, input, operation))
            })
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        let mut failure = None;
        for handle in handles {
            match handle
                .join()
                .map_err(|_| invalid_source())
                .and_then(|result| result)
            {
                Ok(source) => output.push(source),
                Err(error) => {
                    operation.cancel();
                    failure = Some(match failure {
                        None => error,
                        Some(current) => super::super::attempt::prefer_failure(current, error),
                    });
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(output),
        }
    })
}

pub(super) fn replay(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    source: &StagedSource,
    writing: &mut DirectWriting,
    allocator: &mut super::super::Allocator,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let mut file = source.spool.reopen().map_err(storage)?;
    writing.register_source(
        &source.manifest.sha256,
        request.parser.logical_source(&source.manifest.source),
    )?;
    file.rewind().map_err(storage)?;
    let mut reader = std::io::BufReader::new(crate::parquet_store::HashingReader::new(file));
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut bytes = Vec::new();
        (&mut reader)
            .take(MAX_STAGED_ROW + 1)
            .read_until(b'\n', &mut bytes)
            .map_err(storage)?;
        if bytes.is_empty() {
            break;
        }
        if bytes.len() as u64 > MAX_STAGED_ROW || bytes.last() != Some(&b'\n') {
            return Err(invalid_source());
        }
        let row: RecordRow = serde_json::from_slice(&bytes).map_err(storage)?;
        writing.push(row, allocator, &store.case_dir(request.case_id)?, cancel)?;
    }
    if reader.into_inner().finish() != source.normalized_hash {
        return Err(invalid_source());
    }
    Ok(())
}
pub(super) fn acquisition(
    source: StagedSource,
) -> Result<irmind_app::MappedSourceAcquisition, AppError> {
    Ok(irmind_app::MappedSourceAcquisition {
        manifest: source.manifest,
        report: source.report,
        format_sample_sha256: source.sample_hash,
        decoded: source.mapping.ok_or_else(invalid_source)?,
    })
}

fn stage_one(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    mut input: Input,
    cancel: &CancellationToken,
) -> Result<StagedSource, AppError> {
    let path = input.path.clone();
    let initial = crate::parquet_store::local::stream::initial_hash(
        &mut input.file,
        cancel,
        store.profile.as_deref(),
    )?;
    hash_failure(
        store.stage_hashed_source(
            request.case_id,
            input,
            request.parser,
            request.copy_original,
            cancel,
            initial,
        ),
        path,
    )
}
fn hash_failure(
    result: Result<StagedSource, AppError>,
    path: String,
) -> Result<StagedSource, AppError> {
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
