use super::{
    AppError, CancellationToken, CaseId, EventHit, GraphQueryFilter, Instant, ParquetArtifact,
    Predicate, QUERY_DEADLINE, QueryStore, ScanFlow, ScanSpec, complete, recent, text, time_rules,
};
use irmind_app::TimelineEvent;
use std::collections::BTreeMap;

impl QueryStore<'_> {
    pub(crate) fn search_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
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
            return Ok("no indexed matches".into());
        }
        Ok(hits
            .into_iter()
            .map(|hit| {
                let at = hit.at.chars().take(32).collect::<String>();
                let event = hit.annotated_event().chars().take(160).collect::<String>();
                format!("{at} {event} source={}", hit.source())
            })
            .collect::<Vec<_>>()
            .join("\n"))
    }

    pub(crate) fn timeline_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<TimelineEvent>, AppError> {
        let limit = limit.min(100);
        let mut hits = Vec::new();
        let deadline = Instant::now() + QUERY_DEADLINE;
        let rules = time_rules(filter);
        let mut dates = BTreeMap::<&str, Vec<ParquetArtifact>>::new();
        for artifact in artifacts.iter().filter(|artifact| {
            super::super::format::same_family(artifact.schema_version(), "irmind-events-v2")
                && super::super::scan::partition_matches(artifact, filter)
        }) {
            dates
                .entry(artifact.partition_date())
                .or_default()
                .push(artifact.clone());
        }
        let unknown = dates.remove("unknown");
        for group in dates.values().rev().chain(unknown.iter()) {
            let status = self.scan_artifacts(
                ScanSpec {
                    id,
                    artifacts: group,
                    filter,
                    schema: "irmind-events-v2",
                    columns: &["event_time", "event", "source_hash", "record_index"],
                    predicates: &rules,
                    deadline,
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
            if hits.len() >= limit {
                break;
            }
        }
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

    pub(crate) fn raw_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        hash: &str,
        index: usize,
        cancel: &CancellationToken,
    ) -> Result<Option<String>, AppError> {
        let selected = artifacts
            .iter()
            .filter(|artifact| {
                artifact
                    .source_hashes()
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
        artifacts: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let (mut count, mut first, mut last) = (
            0u64,
            None::<super::super::time_cell::TimeCell>,
            None::<super::super::time_cell::TimeCell>,
        );
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
        let mut summary = format!(
            "Parquet records={count}; first={}; last={}",
            first.map_or_else(String::new, |t| t.display()),
            last.map_or_else(String::new, |t| t.display())
        );
        if artifacts.iter().any(|a| matches!(a, ParquetArtifact::V2(v) if v.builder_version == crate::parquet_store::partitioning::BUILDER)) {
            summary.push_str(&partition_coverage(artifacts));
        }
        Ok(summary)
    }
}

fn partition_coverage(artifacts: &[ParquetArtifact]) -> String {
    use irmind_domain::{
        ArtifactSchemaV2, PartitionOverflowReason as Reason, ScopePartitionValue as Value,
    };
    let (mut files, mut overflow, mut cardinality, mut tuples, mut invalid) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    for artifact in artifacts {
        let ParquetArtifact::V2(v) = artifact else {
            continue;
        };
        if v.builder_version != crate::parquet_store::partitioning::BUILDER
            || v.schema != ArtifactSchemaV2::Events
        {
            continue;
        }
        files += 1;
        let has = |reason| {
            v.partition
                .scopes
                .iter()
                .any(|s| s.value == Value::Overflow(reason))
        };
        let card = has(Reason::Cardinality);
        let tuple = has(Reason::TupleBudget);
        let bad = has(Reason::UnrepresentableValue);
        overflow += usize::from(card || tuple || bad);
        cardinality += usize::from(card);
        tuples += usize::from(tuple);
        invalid += usize::from(bad);
    }
    format!(
        "; partitioned event files={files}; overflow files={overflow} (cardinality={cardinality}, tuple-budget={tuples}, unrepresentable-value={invalid})"
    )
}
