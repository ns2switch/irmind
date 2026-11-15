use super::{
    AppError, CancellationToken, CaseId, EventHit, GraphQueryFilter, Instant, ParquetArtifact,
    Predicate, QUERY_DEADLINE, QueryStore, ScanFlow, ScanSpec, recent, time_rules,
};

impl QueryStore<'_> {
    pub(crate) fn entity_timeline_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.entity_timeline_answer(id, artifacts, filter, entity, limit, cancel)?
            .strict()
    }
    pub(crate) fn entity_timeline_answer(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<super::QueryAnswer<String>, AppError> {
        let mut rules = time_rules(filter);
        rules.extend([
            Predicate::Equal("entity_kind", entity.0.into()),
            Predicate::Equal("entity_value", entity.1.into()),
        ]);
        let mut hits = Vec::new();
        let limit = limit.min(20);
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts,
                filter,
                schema: "irmind-entities-v4",
                columns: &["event_time", "event", "source_hash", "record_index"],
                predicates: &rules,
                deadline: Instant::now() + QUERY_DEADLINE,
                cancel,
            },
            |batch| {
                for row in 0..batch.num_rows() {
                    hits.push(EventHit::from_batch(
                        batch,
                        row,
                        artifacts.iter().any(|a| a.precise_metadata().is_some()),
                    )?);
                }
                recent(&mut hits, limit)?;
                Ok(ScanFlow::Continue)
            },
        )?;
        if hits.is_empty() {
            return Ok(super::QueryAnswer::scanned(
                "no entity activity in Parquet".into(),
                status,
            ));
        }
        Ok(super::QueryAnswer::scanned(
            hits.into_iter()
                .map(|hit| {
                    format!(
                        "{} {} source={}",
                        hit.at,
                        hit.annotated_event(),
                        hit.source()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
            status,
        ))
    }

    pub(crate) fn entity_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        kind: &str,
        value: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.entity_answer(id, artifacts, filter, kind, value, cancel)?
            .strict()
    }
    pub(crate) fn entity_answer(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        kind: &str,
        value: &str,
        cancel: &CancellationToken,
    ) -> Result<super::QueryAnswer<String>, AppError> {
        if artifacts.is_empty() {
            return Ok(super::QueryAnswer::complete(format!(
                "{kind} {value}: count=0; first=; last="
            )));
        }
        self.scoped_entity_answer(id, artifacts, filter, kind, value, cancel)
    }
}
