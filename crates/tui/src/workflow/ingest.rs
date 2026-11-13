use super::CaseWorkflow;
use irmind_app::{
    AppError, CancellationToken, CaseId, LargeCaseUseCases, ParserTimeContext,
    StreamingEventParser,
    modules::{ParserCatalog, ParserSelectionRequest, ResolvedParserSelection},
};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) struct IngestRequest<'a> {
    pub id: &'a CaseId,
    pub path: &'a Path,
    pub copy_original: bool,
    pub forced_parser: Option<&'a str>,
    pub analyst_choices: &'a BTreeMap<String, String>,
    pub cancel: &'a CancellationToken,
    pub time_contexts: &'a BTreeMap<String, ParserTimeContext>,
    pub default_time_context: Option<ParserTimeContext>,
}

impl CaseWorkflow<'_, '_> {
    pub(crate) fn ingest_path(
        &self,
        id: &CaseId,
        path: &Path,
        cancel: &CancellationToken,
        progress: impl FnMut(usize, usize, &str),
    ) -> Result<usize, AppError> {
        self.ingest_path_with_copy(id, path, false, cancel, progress)
    }

    pub(crate) fn ingest_path_with_copy(
        &self,
        id: &CaseId,
        path: &Path,
        copy_original: bool,
        cancel: &CancellationToken,
        progress: impl FnMut(usize, usize, &str),
    ) -> Result<usize, AppError> {
        self.ingest_path_with_parser(id, path, copy_original, None, cancel, progress)
    }

    pub(crate) fn ingest_path_with_parser(
        &self,
        id: &CaseId,
        path: &Path,
        copy_original: bool,
        forced_parser: Option<&str>,
        cancel: &CancellationToken,
        mut progress: impl FnMut(usize, usize, &str),
    ) -> Result<usize, AppError> {
        self.ingest_path_with_selections(
            IngestRequest {
                id,
                path,
                copy_original,
                forced_parser,
                analyst_choices: &BTreeMap::new(),
                time_contexts: &BTreeMap::new(),
                default_time_context: None,
                cancel,
            },
            &mut progress,
        )
    }

    pub(crate) fn ingest_path_with_selections(
        &self,
        request: IngestRequest<'_>,
        mut progress: impl FnMut(usize, usize, &str),
    ) -> Result<usize, AppError> {
        let path = request.path;
        let forced_parser = request.forced_parser;
        let files = self.io_ops.input_files(path).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::CannotListSelectedEvidence,
            ))
        })?;
        if let Some(catalog) = self.io_ops.parser_catalog() {
            return self.ingest_detected(request, &files, catalog, &mut progress);
        }
        if forced_parser.is_some()
            || request.default_time_context.is_some()
            || !request.time_contexts.is_empty()
        {
            return Err(AppError::Policy("parser override is unavailable".into()));
        }
        self.ingest_without_catalog(request, &files, &mut progress)
    }

    fn ingest_without_catalog(
        &self,
        request: IngestRequest<'_>,
        files: &[std::path::PathBuf],
        progress: &mut impl FnMut(usize, usize, &str),
    ) -> Result<usize, AppError> {
        let IngestRequest {
            id,
            path,
            copy_original,
            cancel,
            ..
        } = request;
        let total = files.len();
        let (store, parser) = self
            .io_ops
            .large_case_store()
            .zip(self.io_ops.streaming_parser())
            .ok_or(AppError::Policy(
                "signed Parquet ingestion is unavailable".into(),
            ))?;
        let source_root = if path.is_dir() {
            path
        } else {
            path.parent()
                .ok_or(AppError::Policy("selected source has no parent".into()))?
        };
        let sources = files
            .iter()
            .map(|file| {
                self.io_ops.audit_source_name(path, file).map_err(|_| {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                        irmind_app::AdapterStorageError::InvalidSelectedEvidencePath,
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        {
            let use_cases = LargeCaseUseCases {
                engine: self.engine,
                store,
                parser,
            };
            for (group_index, group) in sources.chunks(usize::MAX).enumerate() {
                let ingested =
                    use_cases.ingest_local_batch(id, source_root, group, copy_original, cancel)?;
                for (offset, (source, _)) in ingested.into_iter().enumerate() {
                    let safe_source = self.engine.guard.screen(&source)?.text;
                    progress(group_index * usize::MAX + offset + 1, total, &safe_source);
                }
            }
        }
        Ok(total)
    }

    fn ingest_detected(
        &self,
        request: IngestRequest<'_>,
        files: &[std::path::PathBuf],
        catalog: &ParserCatalog,
        progress: &mut impl FnMut(usize, usize, &str),
    ) -> Result<usize, AppError> {
        let IngestRequest {
            id,
            path,
            copy_original,
            cancel,
            ..
        } = request;
        let source_root = if path.is_dir() {
            path
        } else {
            path.parent()
                .ok_or(AppError::Policy("selected source has no parent".into()))?
        };
        let selected = self.detect_sources(request, files, catalog)?;
        let store = self.io_ops.large_case_store().ok_or(AppError::Policy(
            "signed Parquet ingestion is unavailable".into(),
        ))?;
        let mut done = files.len().saturating_sub(selected.len());
        let mut cursor = 0;
        while cursor < selected.len() {
            let first = &selected[cursor].1.selection;
            let parser_id = &first.parser_id;
            let end = selected[cursor..]
                .iter()
                .take_while(|(_, resolved)| {
                    resolved.selection.parser_id == *parser_id
                        && resolved.selection.parser_version == first.parser_version
                        && resolved.selection.timestamp_context == first.timestamp_context
                        && resolved.selection.cluster_context == first.cluster_context
                })
                .count()
                + cursor;
            let parser = selected[cursor].1.parser.clone();
            let use_cases = LargeCaseUseCases {
                engine: self.engine,
                store,
                parser: parser.as_ref() as &dyn StreamingEventParser,
            };
            let group = &selected[cursor..end];
            let sources = group
                .iter()
                .map(|(source, _)| source.clone())
                .collect::<Vec<_>>();
            let selections = group
                .iter()
                .map(|(source, resolved)| (source.clone(), resolved.selection.clone()))
                .collect::<BTreeMap<_, _>>();
            progress(
                done,
                files.len(),
                "Preparing authenticated sources; uncommitted groups can be cancelled",
            );
            for (source, _) in use_cases
                .ingest_local_batch_selected(
                    id,
                    source_root,
                    &sources,
                    copy_original,
                    &selections,
                    cancel,
                )
                .map_err(|error| {
                    self.engine
                        .annotate_parser_time_error(id, error, catalog, cancel, true)
                })?
            {
                done += 1;
                let safe = self.engine.guard.screen(&source)?.text;
                progress(done, files.len(), &safe);
            }
            cursor = end;
        }
        Ok(done)
    }

    fn detect_sources(
        &self,
        request: IngestRequest<'_>,
        files: &[std::path::PathBuf],
        catalog: &ParserCatalog,
    ) -> Result<Vec<(String, ResolvedParserSelection)>, AppError> {
        let IngestRequest {
            id,
            path,
            forced_parser,
            analyst_choices,
            cancel,
            ..
        } = request;
        let source_root = if path.is_dir() {
            path
        } else {
            path.parent()
                .ok_or(AppError::Policy("selected source has no parent".into()))?
        };
        let indexed = self
            .engine
            .audit_log
            .entries(id)?
            .into_iter()
            .map(|entry| irmind_app::SourceManifestV1::decode_signed(entry.kind, &entry.payload))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AppError::Policy("invalid signed source manifest".into()))?
            .into_iter()
            .flatten()
            .map(|source| (source.source.clone(), source))
            .collect::<BTreeMap<_, _>>();
        let mut selected = Vec::with_capacity(files.len());
        for file in files {
            let source = self
                .io_ops
                .audit_source_name(path, file)
                .map_err(|_| AppError::Policy("invalid selected evidence path".into()))?;
            if let Some(existing) = indexed.get(&source) {
                self.io_ops
                    .large_case_store()
                    .ok_or(AppError::Policy(
                        "signed Parquet ingestion is unavailable".into(),
                    ))?
                    .verify_local_source(source_root, existing, cancel)?;
                continue;
            }
            let sample = self
                .io_ops
                .read_format_sample(file)
                .map_err(|_| AppError::Policy("cannot read bounded format sample".into()))?;
            let context = request
                .time_contexts
                .get(&source)
                .copied()
                .or(request.default_time_context);
            let resolved = catalog.select_source(ParserSelectionRequest {
                source: &source,
                sample: &sample,
                parser_override: forced_parser
                    .or_else(|| analyst_choices.get(&source).map(String::as_str)),
                forced: forced_parser.is_some(),
                time_context: context,
                cluster_context: None,
            });
            let resolved = resolved.map_err(|error| {
                self.engine
                    .annotate_parser_time_error(id, error, catalog, cancel, true)
            })?;
            selected.push((source, resolved));
        }
        selected.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(selected)
    }
}
