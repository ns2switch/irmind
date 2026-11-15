use super::{AppError, CancellationToken, CaseId, GraphQueryFilter, ParquetArtifact, QueryStore};

impl QueryStore<'_> {
    pub(crate) fn path_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        from: (&str, &str),
        to: (&str, &str),
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.path_answer(id, artifacts, filter, from, to, cancel)
            .map(|answer| answer.value)
    }
    pub(crate) fn path_answer(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        from: (&str, &str),
        to: (&str, &str),
        cancel: &CancellationToken,
    ) -> Result<super::QueryAnswer<String>, AppError> {
        self.scoped_path_answer(id, artifacts, filter, from, to, cancel)
    }
}
