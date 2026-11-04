use super::{
    AppError, CancellationToken, CaseId, EventHit, GraphQueryFilter, Instant, ParquetArtifact,
    Predicate, QUERY_DEADLINE, QueryStore, ScanFlow, ScanSpec, complete, recent, time_rules,
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
                    hits.push(EventHit::from_batch(
                        batch,
                        row,
                        artifacts
                            .iter()
                            .any(|a| matches!(a, ParquetArtifact::V2(_))),
                    )?);
                }
                recent(&mut hits, limit)?;
                Ok(ScanFlow::Continue)
            },
        )?;
        complete(status)?;
        if hits.is_empty() {
            return Ok("no entity activity in Parquet".into());
        }
        Ok(hits
            .into_iter()
            .map(|hit| {
                format!(
                    "{} {} source={}",
                    hit.at,
                    hit.annotated_event(),
                    hit.source()
                )
            })
            .collect::<Vec<_>>()
            .join("\n"))
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
        let mut rules = time_rules(filter);
        rules.extend([
            Predicate::Equal("entity_kind", kind.into()),
            Predicate::Equal("entity_value", value.into()),
        ]);
        let (mut count, mut first, mut last) = (
            0u64,
            None::<super::super::time_cell::TimeCell>,
            None::<super::super::time_cell::TimeCell>,
        );
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
                    let at = super::super::time_cell::TimeCell::from_batch(batch, row)?;
                    count += 1;
                    if at.time.is_some() {
                        if first
                            .as_ref()
                            .map(|old| at.compare(old, false))
                            .transpose()?
                            .is_none_or(std::cmp::Ordering::is_lt)
                        {
                            first = Some(at.clone());
                        }
                        if last
                            .as_ref()
                            .map(|old| at.compare(old, false))
                            .transpose()?
                            .is_none_or(std::cmp::Ordering::is_gt)
                        {
                            last = Some(at);
                        }
                    }
                }
                Ok(ScanFlow::Continue)
            },
        )?;
        complete(status)?;
        Ok(format!(
            "{kind} {value}: count={count}; first={}; last={}",
            first.map_or_else(String::new, |t| t.display()),
            last.map_or_else(String::new, |t| t.display())
        ))
    }
}
