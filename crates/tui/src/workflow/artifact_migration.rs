use super::{AppError, CancellationToken, CaseId, CaseWorkflow, LargeCaseUseCases, Path};

impl CaseWorkflow<'_, '_> {
    pub(crate) fn migrate_artifacts_v2(
        &self,
        id: &CaseId,
        root: Option<&Path>,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let (store, parser) = self
            .io_ops
            .large_case_store()
            .zip(self.io_ops.streaming_parser())
            .ok_or_else(|| AppError::Policy("large-case storage is unavailable".into()))?;
        let router = self
            .io_ops
            .parser_catalog()
            .map(|catalog| catalog.rebuild_router(&self.engine.audit_log.entries(id)?))
            .transpose()?;
        LargeCaseUseCases {
            engine: self.engine,
            store,
            parser: router.as_ref().map_or(parser, |router| {
                router as &dyn irmind_app::StreamingEventParser
            }),
        }
        .migrate_artifacts_v2(id, root, cancel)
    }
}
