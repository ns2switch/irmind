use super::CaseWorkflow;
use irmind_app::{
    AppError, CancellationToken, CaseId, LargeCaseUseCases, ParserSelection, ParserSelectionMode,
    StreamingEventParser,
    modules::{ParserCatalog, ParserChoice},
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
        let IngestRequest {
            id,
            path,
            copy_original,
            forced_parser,
            analyst_choices: _,
            cancel,
        } = request;
        let files = self.io_ops.input_files(path).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::CannotListSelectedEvidence,
            ))
        })?;
        if let Some(catalog) = self.io_ops.parser_catalog() {
            return self.ingest_detected(request, &files, catalog, &mut progress);
        }
        if forced_parser.is_some() {
            return Err(AppError::Policy("parser override is unavailable".into()));
        }
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
            for (group_index, group) in sources.chunks(4).enumerate() {
                let ingested =
                    use_cases.ingest_local_batch(id, source_root, group, copy_original, cancel)?;
                for (offset, (source, _)) in ingested.into_iter().enumerate() {
                    let safe_source = self.engine.guard.screen(&source)?.text;
                    progress(group_index * 4 + offset + 1, total, &safe_source);
                }
            }
            let bundles = use_cases.compact_case(id, cancel)?;
            if bundles > 0 {
                progress(
                    total,
                    total,
                    &format!("Created {bundles} signed Parquet bundles"),
                );
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
        let mut last_parser = None;
        while cursor < selected.len() {
            let parser_id = &selected[cursor].1.parser_id;
            let end = selected[cursor..]
                .iter()
                .take(4)
                .take_while(|(_, metadata)| metadata.parser_id == *parser_id)
                .count()
                + cursor;
            let parser = catalog.get(parser_id)?;
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
            let selections = group.iter().cloned().collect::<BTreeMap<_, _>>();
            for (source, _) in use_cases.ingest_local_batch_selected(
                id,
                source_root,
                &sources,
                copy_original,
                &selections,
                cancel,
            )? {
                done += 1;
                let safe = self.engine.guard.screen(&source)?.text;
                progress(done, files.len(), &safe);
            }
            last_parser = Some(parser);
            cursor = end;
        }
        if let Some(parser) = last_parser {
            let use_cases = LargeCaseUseCases {
                engine: self.engine,
                store,
                parser: parser.as_ref() as &dyn StreamingEventParser,
            };
            let bundles = use_cases.compact_case(id, cancel)?;
            if bundles > 0 {
                progress(
                    files.len(),
                    files.len(),
                    &format!("Created {bundles} signed Parquet bundles"),
                );
            }
        }
        Ok(files.len())
    }

    fn detect_sources(
        &self,
        request: IngestRequest<'_>,
        files: &[std::path::PathBuf],
        catalog: &ParserCatalog,
    ) -> Result<Vec<(String, ParserSelection)>, AppError> {
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
            let choice = catalog.detect(&source, &sample);
            let (parser_id, confidence, mode) = resolve_parser_choice(
                &source,
                choice,
                forced_parser.or_else(|| analyst_choices.get(&source).map(String::as_str)),
                forced_parser.is_some(),
                catalog,
            )?;
            let parser = catalog.get(&parser_id)?;
            selected.push((
                source,
                ParserSelection {
                    parser_id,
                    parser_version: parser.streaming_version().into(),
                    confidence,
                    mode,
                    timestamp_context: None,
                    format_sample_sha256: irmind_app::sha256(&sample),
                },
            ));
        }
        selected.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(selected)
    }
}

fn resolve_parser_choice(
    source: &str,
    choice: ParserChoice,
    selected: Option<&str>,
    forced: bool,
    catalog: &ParserCatalog,
) -> Result<(String, u8, ParserSelectionMode), AppError> {
    if let Some(id) = selected {
        catalog.get(id)?;
        let confidence = match &choice {
            ParserChoice::Auto(candidate) if candidate.id == id => candidate.confidence.value(),
            ParserChoice::NeedsAnalyst(candidates) => candidates
                .iter()
                .find(|candidate| candidate.id == id)
                .map_or(0, |candidate| candidate.confidence.value()),
            _ => 0,
        };
        return Ok((
            id.into(),
            confidence,
            if forced {
                ParserSelectionMode::Forced
            } else {
                ParserSelectionMode::Analyst
            },
        ));
    }
    match choice {
        ParserChoice::Auto(candidate) => Ok((
            candidate.id.into(),
            candidate.confidence.value(),
            ParserSelectionMode::Automatic,
        )),
        ParserChoice::NeedsAnalyst(candidates) => Err(AppError::ParserSelection {
            source_name: source.into(),
            candidates: candidates
                .into_iter()
                .map(|candidate| (candidate.id.into(), candidate.confidence.value()))
                .collect(),
        }),
        ParserChoice::Unsupported => Err(AppError::ParserSelection {
            source_name: source.into(),
            candidates: catalog
                .available()
                .into_iter()
                .map(|(id, _)| (id.into(), 0))
                .collect(),
        }),
    }
}
