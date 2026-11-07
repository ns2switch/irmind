//! Scoped identities are occurrences, never implicit directed attack edges.
mod entity;
mod legacy;
mod node;
mod path;
mod scan;
use super::{
    AppError, CancellationToken, CaseId, GraphQueryFilter, ParquetArtifact, QUERY_DEADLINE,
    QueryStore,
};
use crate::parquet_store::scan::{ScanSpec, ScanStatus};
use node::{Node, Peer};
use scan::Selection;
use std::time::Instant;

pub(super) fn available(artifacts: &[ParquetArtifact]) -> bool {
    artifacts
        .iter()
        .any(|a| matches!(a,ParquetArtifact::V2(v) if v.schema.is_common()))
}
fn spec<'a>(
    id: &'a CaseId,
    artifacts: &'a [ParquetArtifact],
    filter: &'a GraphQueryFilter,
    cancel: &'a CancellationToken,
    deadline: Instant,
) -> ScanSpec<'a> {
    ScanSpec {
        id,
        artifacts,
        filter,
        cancel,
        deadline,
        schema: "irmind-coobservations-v1",
        columns: &[],
        predicates: &[],
    }
}
impl QueryStore<'_> {
    pub(in crate::parquet_store::query) fn scoped_neighbors(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let selected = Selection {
            kind: entity.0,
            value: entity.1,
            scope: None,
        };
        let result = self.scoped_candidates(
            spec(
                id,
                artifacts,
                filter,
                cancel,
                Instant::now() + QUERY_DEADLINE,
            ),
            selected,
        )?;
        super::complete(result.status)?;
        let mut rows = result.neighbors.into_iter().collect::<Vec<_>>();
        rows.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit.min(20));
        let mut output = if rows.is_empty() {
            "no neighbors in the bounded Parquet query; refine the entity".into()
        } else {
            rows.into_iter()
                .map(|(node, (count, _))| format!("{} co-observed {count} times", node.display()))
                .collect::<Vec<_>>()
                .join("\n")
        };
        if result.sampled {
            output.push_str("\nPartial result: sampled 4096 matching records; refine the entity.");
        }
        Ok(output)
    }
}
