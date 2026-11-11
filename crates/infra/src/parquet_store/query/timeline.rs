use super::{
    AppError, CancellationToken, CaseId, EventHit, GraphQueryFilter, Instant, ParquetArtifact,
    QUERY_DEADLINE, QueryStore, ScanSpec, complete, time_rules,
};
use irmind_app::TimelineEvent;

impl QueryStore<'_> {
    pub(crate) fn timeline_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<TimelineEvent>, AppError> {
        let rules = time_rules(filter);
        let hits = self.timeline_hits(
            ScanSpec {
                id,
                artifacts,
                filter,
                schema: "irmind-events-v4",
                columns: &["event_time", "event", "source_hash", "record_index"],
                predicates: &rules,
                deadline: Instant::now() + QUERY_DEADLINE,
                cancel,
            },
            limit.min(100),
            true,
        )?;
        hits.into_iter()
            .map(|hit| {
                Ok(TimelineEvent {
                    at: hit.at.clone(),
                    event: hit.annotated_event(),
                    evidence_hash: hit.hash,
                    record_index: usize::try_from(hit.index).map_err(super::super::storage)?,
                })
            })
            .collect()
    }

    fn timeline_hits(
        &self,
        spec: ScanSpec<'_>,
        limit: usize,
        newest: bool,
    ) -> Result<Vec<EventHit>, AppError> {
        let files = self
            .store
            .time_ordered_artifacts(&spec, newest, self.source_names)?;
        let precise = spec
            .artifacts
            .iter()
            .any(|a| a.precise_metadata().is_some());
        let mut hits = Vec::<EventHit>::new();
        let mut units = std::collections::BTreeMap::new();
        for (bound, artifact) in files {
            if hits.len() >= limit
                && hits.last().is_some_and(|last| {
                    bound.cannot_beat(last.time.time.map(irmind_app::IndexedTime::instant), newest)
                })
            {
                // All remaining authenticated bounds are no better. Strict
                // inequality preserves every source/offset tie at the cutoff.
                break;
            }
            let cutoff = (hits.len() >= limit)
                .then(|| {
                    hits.last()
                        .map(|h| super::super::scan::TimeCutoff(h.time.clone()))
                })
                .flatten();
            let status = self.store.scan_time_ordered_file(
                ScanSpec {
                    artifacts: std::slice::from_ref(artifact),
                    ..spec
                },
                self.source_names,
                newest,
                cutoff,
                |batch| {
                    super::super::time_cell::validate_source_units(batch, &mut units)?;
                    super::retained::retain_batch(batch, &mut hits, limit, newest, precise)?;
                    Ok(if hits.len() >= limit {
                        hits.last()
                            .map(|h| super::super::scan::TimeCutoff(h.time.clone()))
                    } else {
                        None
                    })
                },
            )?;
            complete(status)?;
        }
        Ok(hits)
    }
}

#[cfg(test)]
mod tests;
