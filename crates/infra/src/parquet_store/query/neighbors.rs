use super::{AppError, CancellationToken, CaseId, GraphQueryFilter, ParquetArtifact, QueryStore};

impl QueryStore<'_> {
    pub(crate) fn neighbors_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.neighbors_answer(id, artifacts, filter, entity, limit, cancel)?
            .strict()
    }
    pub(crate) fn neighbors_answer(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<super::QueryAnswer<String>, AppError> {
        self.scoped_neighbors_answer(id, artifacts, filter, entity, limit, cancel)
    }
}
