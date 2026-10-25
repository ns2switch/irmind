use crate::WorkspaceIo;
use irmind_app::{AppError, CancellationToken, CaseId, Engine, LlmPort, SealPreview, Severity};
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
        mut progress: impl FnMut(usize, usize, &str),
    ) -> Result<usize, AppError> {
        let files = self
            .io_ops
            .input_files(path)
            .map_err(|_| AppError::Storage("cannot list selected evidence".into()))?;
        let total = files.len();
        for (index, file) in files.iter().enumerate() {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let bytes = self
                .io_ops
                .read_evidence(file)
                .map_err(|_| AppError::Storage("cannot read selected evidence".into()))?;
            let source = self
                .io_ops
                .audit_source_name(path, file)
                .map_err(|_| AppError::Storage("invalid selected evidence path".into()))?;
            self.engine.ingest_cancelable(id, &bytes, &source, cancel)?;
            progress(index + 1, total, &source);
        }
        Ok(total)
    }

    pub(crate) fn investigate(
        &self,
        id: &CaseId,
        alert: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let model = self
            .model
            .ok_or_else(|| AppError::Policy("no LLM selected".into()))?;
        self.engine
            .investigate_with_cancel(id, alert, model, cancel)
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
        self.engine.verify_cancelable(id, cancel)
    }

    pub(crate) fn rebuild_graph(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.engine.rebuild_graph_cancelable(id, cancel)
    }

    pub(crate) fn seal(&self, id: &CaseId) -> Result<(), AppError> {
        self.engine.seal(id)
    }

    pub(crate) fn prepare_seal(&self, id: &CaseId) -> Result<SealPreview, AppError> {
        self.engine.prepare_seal(id)
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
        self.engine.verify_cancelable(id, cancel)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.io_ops
            .export_case(self.engine, id, path)
            .map_err(|_| AppError::Storage("case export failed".into()))
    }
}
