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
        super::require_current(artifacts)?;
        self.scoped_neighbors(id, artifacts, filter, entity, limit, cancel)
    }
}
