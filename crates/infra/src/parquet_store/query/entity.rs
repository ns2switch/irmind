use super::{
    AppError, CancellationToken, CaseId, EventHit, GraphQueryFilter, Instant, ParquetArtifactV1,
    ParquetStore, Predicate, QUERY_DEADLINE, ScanFlow, ScanSpec, complete, recent, text,
    time_rules,
};

impl ParquetStore {
    pub(crate) fn entity_timeline_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
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
                schema: "irmind-entities-v1",
                columns: &["event_time", "event", "source_hash", "record_index"],
                predicates: &rules,
                deadline: Instant::now() + QUERY_DEADLINE,
                cancel,
            },
            |batch| {
                for row in 0..batch.num_rows() {
                    hits.push(EventHit::from_batch(batch, row)?);
                }
                recent(&mut hits, limit);
                Ok(ScanFlow::Continue)
            },
        )?;
        complete(status)?;
        if hits.is_empty() {
            return Ok("no entity activity in Parquet".into());
        }
        Ok(hits
            .into_iter()
            .map(|hit| format!("{} {} source={}", hit.at, hit.event, hit.source()))
            .collect::<Vec<_>>()
            .join("\n"))
    }

    pub(crate) fn entity_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        kind: &str,
        value: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let mut rules = time_rules(filter);
        rules.extend([
            Predicate::Equal("entity_kind", kind.into()),
            Predicate::Equal("entity_value", value.into()),
        ]);
        let (mut count, mut first, mut last) = (0u64, None::<String>, None::<String>);
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts,
                filter,
                schema: "irmind-entities-v1",
                columns: &["event_time"],
                predicates: &rules,
                deadline: Instant::now() + QUERY_DEADLINE,
                cancel,
            },
            |batch| {
                for row in 0..batch.num_rows() {
                    let at = text(batch, "event_time", row)?;
                    count += 1;
                    if first.as_deref().is_none_or(|old| at < old) {
                        first = Some(at.into());
                    }
                    if last.as_deref().is_none_or(|old| at > old) {
                        last = Some(at.into());
                    }
                }
                Ok(ScanFlow::Continue)
            },
        )?;
        complete(status)?;
        Ok(format!(
            "{kind} {value}: count={count}; first={}; last={}",
            first.unwrap_or_default(),
            last.unwrap_or_default()
        ))
    }
}
