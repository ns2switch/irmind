use crate::WorkspaceIo;
use irmind_app::{
    AppError, AuditEventKind, CancellationToken, CaseId, Engine, LargeCaseUseCases, LlmPort,
    SealPreview, SealedParquetMigrationV1, Severity, SourceCheckMode,
};
use std::path::Path;

/// Presentation controller shared by keyboard actions and `TestBackend` tests.
#[derive(Clone, Copy)]
pub(crate) struct CaseWorkflow<'a, 'ports> {
    pub engine: &'a Engine<'ports>,
    pub model: Option<&'a dyn LlmPort>,
    pub io_ops: &'a dyn WorkspaceIo,
}

impl CaseWorkflow<'_, '_> {
    pub(crate) fn create_case(
        &self,
        title: &str,
        severity: Severity,
        scope: &str,
    ) -> Result<CaseId, AppError> {
        Ok(self
            .engine
            .create_case_with_severity(title, severity, scope)?
            .id)
    }

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
        mut progress: impl FnMut(usize, usize, &str),
    ) -> Result<usize, AppError> {
        let files = self.io_ops.input_files(path).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::CannotListSelectedEvidence,
            ))
        })?;
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

    pub(crate) fn investigate(
        &self,
        id: &CaseId,
        alert: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let model = self.model.ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::NoLLMSelected,
            ))
        })?;
        self.engine
            .investigate_with_cancel(id, alert, model, cancel)
    }

    pub(crate) fn investigate_with_progress(
        &self,
        id: &CaseId,
        alert: &str,
        cancel: &CancellationToken,
        on_text: &(dyn Fn(irmind_app::ModelProgress) + Send + Sync),
    ) -> Result<String, AppError> {
        let model = self
            .model
            .ok_or(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::NoLLMSelected,
            )))?;
        self.engine
            .investigate_with_progress(id, alert, model, cancel, on_text)
    }

    pub(crate) fn approve(
        &self,
        id: &CaseId,
        request_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.engine.approve_with_cancel(id, request_id, cancel)
    }

    pub(crate) fn verify(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        if self.has_source_manifests(id)? || self.has_parquet_artifacts(id)? {
            return Err(AppError::Policy(
                "select the original source root with /verify <path>".into(),
            ));
        }
        self.engine.verify_cancelable(id, cancel)
    }

    pub(crate) fn verify_with_source_root(
        &self,
        id: &CaseId,
        root: &Path,
        mode: SourceCheckMode,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let (store, parser) = self
            .io_ops
            .large_case_store()
            .zip(self.io_ops.streaming_parser())
            .ok_or(AppError::Policy("large-case storage is unavailable".into()))?;
        let large = LargeCaseUseCases {
            engine: self.engine,
            store,
            parser,
        };
        let report = large.verify_sources(id, root, mode, cancel)?;
        if !report.missing_or_changed.is_empty() {
            return Err(AppError::Policy(format!(
                "{} original sources are missing or changed",
                report.missing_or_changed.len()
            )));
        }
        Ok(format!(
            "Verified {} of {} original sources; {} were not sampled",
            report.checked, report.total, report.unchecked
        ))
    }

    pub(crate) fn verify_parquet_rebuild(
        &self,
        id: &CaseId,
        root: &Path,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let (store, parser) = self
            .io_ops
            .large_case_store()
            .zip(self.io_ops.streaming_parser())
            .ok_or(AppError::Policy("large-case storage is unavailable".into()))?;
        LargeCaseUseCases {
            engine: self.engine,
            store,
            parser,
        }
        .verify_parquet_rebuild(id, root, cancel)
    }

    pub(crate) fn migrate_legacy(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let (store, parser) = self
            .io_ops
            .large_case_store()
            .zip(self.io_ops.streaming_parser())
            .ok_or(AppError::Policy("large-case storage is unavailable".into()))?;
        let use_cases = LargeCaseUseCases {
            engine: self.engine,
            store,
            parser,
        };
        let converted = use_cases.migrate_legacy(id, cancel)?;
        if !self.engine.repo.get_case(id)?.sealed {
            use_cases.compact_case(id, cancel)?;
        }
        Ok(converted)
    }

    pub(crate) fn has_source_manifests(&self, id: &CaseId) -> Result<bool, AppError> {
        Ok(self
            .engine
            .audit_log
            .entries(id)?
            .iter()
            .any(|entry| entry.kind == AuditEventKind::SourceManifestV1))
    }

    fn has_parquet_artifacts(&self, id: &CaseId) -> Result<bool, AppError> {
        let case_chain = self
            .engine
            .audit_log
            .entries(id)?
            .iter()
            .any(|entry| entry.kind == AuditEventKind::ParquetArtifactV1);
        for operation in self.engine.audit_log.operations(id)? {
            if SealedParquetMigrationV1::decode(&operation.operation)
                .map_err(|_| AppError::InvalidChain(operation.seq))?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(case_chain)
    }

    pub(crate) fn rebuild_graph(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.migrate_legacy(id, cancel)
    }

    pub(crate) fn verify_graph(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        if self.has_source_manifests(id)? {
            return Err(AppError::Policy(
                "use /verify-graph <source-root> to rebuild and compare Parquet".into(),
            ));
        }
        if self.has_parquet_artifacts(id)? {
            return self.verify_parquet_rebuild(id, Path::new("."), cancel);
        }
        Err(AppError::Policy(
            "no signed Parquet artifacts; migrate copied evidence first".into(),
        ))
    }

    pub(crate) fn seal(&self, id: &CaseId) -> Result<(), AppError> {
        self.engine.seal(id)
    }

    pub(crate) fn prepare_seal(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<SealPreview, AppError> {
        self.engine.prepare_seal_cancelable(id, cancel)
    }

    pub(crate) fn seal_prepared(&self, preview: &SealPreview) -> Result<(), AppError> {
        self.engine.seal_prepared(preview)
    }

    pub(crate) fn export(
        &self,
        id: &CaseId,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.export_with_options(id, path, None, false, cancel)
    }

    pub(crate) fn export_with_options(
        &self,
        id: &CaseId,
        path: &Path,
        source_root: Option<&Path>,
        include_originals: bool,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if self.has_source_manifests(id)? || self.has_parquet_artifacts(id)? {
            let exporter = self
                .io_ops
                .large_case_exporter()
                .ok_or(AppError::Policy("large-case export is unavailable".into()))?;
            irmind_app::export_case_v4(
                self.engine,
                exporter,
                id,
                path,
                source_root,
                include_originals,
                cancel,
            )
        } else {
            if include_originals {
                return Err(AppError::Policy(
                    "this case already uses the copied-evidence export format".into(),
                ));
            }
            irmind_app::export_case(self.engine, self.io_ops.case_exporter(), id, path, cancel)
        }
    }
}
