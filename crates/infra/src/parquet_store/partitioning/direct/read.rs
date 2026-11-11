mod prefix;
use super::super::super::local::stream::{VerifiedInput, initial_hash};
use super::super::staging::{Input, MAX_STAGED_ROW, StagedSource, source_sample};
use super::{AppError, CancellationToken, MappedIngestRequest, ParquetStore, invalid_source};
use crate::parquet_store::writer::direct::DirectWriting;
use crate::parquet_store::{RecordRow, storage};
use irmind_domain::EvidenceHash;
use std::collections::BTreeMap;
use std::io::{BufRead, Read as _, Seek as _};

pub(super) enum Plan {
    Stream(Input, EvidenceHash),
    Sorted(Box<StagedSource>),
}
#[derive(Clone, Copy)]
pub(super) struct OrderHints<'a> {
    pub(super) ordered: &'a BTreeMap<String, EvidenceHash>,
    pub(super) first_disordered: (&'a str, &'a EvidenceHash),
}
type Initial = (std::fs::Metadata, [u8; 32], u64);

pub(super) fn plan(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    inputs: Vec<Input>,
    hints: OrderHints<'_>,
    cancel: &CancellationToken,
) -> Result<Vec<Plan>, AppError> {
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
                        let initial =
                            initial_hash(&mut input.file, cancel, store.profile.as_deref())?;
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
            .map(|(input, initial)| plan_hashed(store, request, input, hints, cancel, initial))
            .collect();
    }
    parallel_plan(store, request, inputs, hints, cancel)
}
fn parallel_plan(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    inputs: Vec<Input>,
    hints: OrderHints<'_>,
    cancel: &CancellationToken,
) -> Result<Vec<Plan>, AppError> {
    let operation = cancel.child_token();
    std::thread::scope(|scope| {
        let handles = inputs
            .into_iter()
            .map(|input| {
                let operation = &operation;
                scope.spawn(move || plan_one(store, request, input, hints, operation))
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
pub(super) fn acquisition(source: StagedSource) -> irmind_app::MappedSourceAcquisition {
    irmind_app::MappedSourceAcquisition {
        manifest: source.manifest,
        report: source.report,
        format_sample_sha256: source.sample_hash,
        decoded: source.mapping,
    }
}

fn plan_one(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    mut input: Input,
    hints: OrderHints<'_>,
    cancel: &CancellationToken,
) -> Result<Plan, AppError> {
    if let Some(hash) = hints.ordered.get(&input.path) {
        return Ok(Plan::Stream(input, hash.clone()));
    }
    let initial = initial_hash(&mut input.file, cancel, store.profile.as_deref())?;
    plan_hashed(store, request, input, hints, cancel, initial)
}

fn plan_hashed(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    input: Input,
    hints: OrderHints<'_>,
    cancel: &CancellationToken,
    initial: Initial,
) -> Result<Plan, AppError> {
    let path = input.path.clone();
    let hash = EvidenceHash::from_bytes(initial.1);
    if let Some(expected) = hints.ordered.get(&path) {
        if expected != &hash {
            return Err(source_changed(path)?);
        }
        return Ok(Plan::Stream(input, hash));
    }
    let (first_path, first_hash) = hints.first_disordered;
    if path == first_path && &hash != first_hash {
        return Err(source_changed(path)?);
    }
    if path != first_path {
        return hash_failure(
            prefix::plan_source(store, request, input, initial, hash, cancel),
            &path,
        );
    }
    let staged = hash_failure(
        store.stage_hashed_source(
            request.case_id,
            input,
            request.parser,
            request.copy_original,
            cancel,
            initial,
        ),
        &path,
    )?;
    Ok(Plan::Sorted(Box::new(staged)))
}

pub(super) fn source_changed(path: String) -> Result<AppError, AppError> {
    Ok(AppError::SourceFailure(
        irmind_app::RejectedSource::try_new(path, irmind_app::SourceFailureReason::Hash, vec![])?,
    ))
}

fn hash_failure<T>(result: Result<T, AppError>, path: &str) -> Result<T, AppError> {
    match result {
        Err(AppError::EvidenceMismatch(_)) => Err(source_changed(path.to_owned())?),
        other => other,
    }
}

#[cfg(test)]
mod tests;
