use super::{
    AppError, CancellationToken, CaseId, EventHit, GraphQueryFilter, Instant, ParquetArtifactV1,
    ParquetStore, Predicate, QUERY_DEADLINE, ScanFlow, ScanSpec, complete, recent, text,
    time_rules,
};
use irmind_app::TimelineEvent;

impl ParquetStore {
    pub(crate) fn search_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        term: &str,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if term.trim().is_empty() || term.len() > 128 || !(1..=20).contains(&limit) {
            return Err(AppError::Policy("invalid Parquet search arguments".into()));
        }
        let mut hits = Vec::new();
        let mut rules = time_rules(filter);
        rules.push(Predicate::ContainsIgnoreCase("text", term.into()));
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts,
                filter,
                schema: "irmind-events-v2",
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
            return Ok("no indexed matches".into());
        }
        Ok(hits
            .into_iter()
            .map(|hit| {
                let at = hit.at.chars().take(32).collect::<String>();
                let event = hit.event.chars().take(160).collect::<String>();
                format!("{at} {event} source={}", hit.source())
            })
            .collect::<Vec<_>>()
            .join("\n"))
    }

    pub(crate) fn timeline_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<TimelineEvent>, AppError> {
        let limit = limit.min(100);
        let mut hits = Vec::new();
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts,
                filter,
                schema: "irmind-events-v2",
                columns: &["event_time", "event", "source_hash", "record_index"],
                predicates: &time_rules(filter),
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
        hits.into_iter()
            .map(|hit| {
                Ok(TimelineEvent {
                    at: hit.at,
                    event: hit.event,
                    evidence_hash: hit.hash,
                    record_index: usize::try_from(hit.index).map_err(super::super::storage)?,
                })
            })
            .collect()
    }

    pub(crate) fn raw_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        hash: &str,
        index: usize,
        cancel: &CancellationToken,
    ) -> Result<Option<String>, AppError> {
        let selected = artifacts
            .iter()
            .filter(|artifact| {
                artifact
                    .source_hashes
                    .iter()
                    .any(|item| item.as_str() == hash)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut value = None;
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts: &selected,
                filter: &GraphQueryFilter::default(),
                schema: "irmind-events-v2",
                columns: &["text"],
                predicates: &[
                    Predicate::Equal("source_hash", hash.into()),
                    Predicate::Index(u64::try_from(index).map_err(super::super::storage)?),
                ],
                deadline: Instant::now() + QUERY_DEADLINE,
                cancel,
            },
            |batch| {
                if batch.num_rows() > 0 {
                    value = Some(text(batch, "text", 0)?.into());
                    Ok(ScanFlow::Stop)
                } else {
                    Ok(ScanFlow::Continue)
                }
            },
        )?;
        complete(status)?;
        Ok(value)
    }

    pub(crate) fn summary_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let (mut count, mut first, mut last) = (0u64, None::<String>, None::<String>);
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts,
                filter: &GraphQueryFilter::default(),
                schema: "irmind-events-v2",
                columns: &["event_time"],
                predicates: &[],
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
            "Parquet records={count}; first={}; last={}",
            first.unwrap_or_default(),
            last.unwrap_or_default()
        ))
    }
}
