//! Mandatory frozen-generation and source filtering for delegated local reads.
use crate::LocalStore;
use irmind_app::{
    AppError, AuditLog, CancellationToken, EvidenceStore, SourceEvidenceReader,
    subagents::{
        TaskEvidenceQueries, TaskEvidenceQuery, TaskEvidenceResult, TaskQueryPartialReason,
        VerifiedTaskQueryView,
    },
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

struct TaskQueries {
    store: Arc<LocalStore>,
    originals: Arc<dyn SourceEvidenceReader>,
}
impl LocalStore {
    pub fn task_evidence_queries(
        self: &Arc<Self>,
        originals: Arc<dyn SourceEvidenceReader>,
    ) -> Arc<dyn TaskEvidenceQueries> {
        Arc::new(TaskQueries {
            store: Arc::clone(self),
            originals,
        })
    }
}

impl TaskEvidenceQueries for TaskQueries {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        cancel: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        check(cancel)?;
        query.validate(view)?;
        let coverage = query
            .filter()
            .and_then(irmind_domain::GraphQueryFilter::coverage_notice);
        let catalog = self.store.query_catalog_at(
            view.case(),
            view.generation_seq(),
            view.generation_hash().as_bytes(),
        )?;
        if view
            .sources()
            .iter()
            .any(|hash| !catalog.source_names.contains_key(hash))
        {
            return Err(AppError::Policy("TaskSourceViewUnsupported: a task source is absent from its frozen query generation".into()));
        }
        let queries = self
            .store
            .parquet
            .queries_for_sources(&catalog.source_names, view.sources());
        let indexed = !matches!(
            &query,
            TaskEvidenceQuery::EvidenceRead { .. }
                | TaskEvidenceQuery::EvidenceSearch { .. }
                | TaskEvidenceQuery::RawRecords { .. }
        );
        let incomplete = indexed && self.incomplete_coverage(view, coverage.is_some(), cancel)?;
        let result = match query {
            TaskEvidenceQuery::EvidenceRead { hash, limit } => {
                let mut bytes = self.store.get_evidence(view.case(), hash.as_str())?;
                let clipped = bytes.len() > limit * 500;
                bytes.truncate(limit * 500);
                let text = String::from_utf8_lossy(&bytes).into_owned();
                if clipped {
                    TaskEvidenceResult::PartialText {
                        text,
                        reason: TaskQueryPartialReason::ExcerptLimit,
                    }
                } else {
                    TaskEvidenceResult::Text(text)
                }
            }
            TaskEvidenceQuery::EvidenceSearch { query, limit } => {
                self.search(view, &query, limit, cancel)?
            }
            TaskEvidenceQuery::RawRecords {
                hash,
                index,
                original: true,
            } => TaskEvidenceResult::Original(Box::new(self.originals.read_verified_record(
                view.case(),
                &hash,
                index,
                cancel,
            )?)),
            TaskEvidenceQuery::RawRecords {
                hash,
                index,
                original: false,
            } => raw(&queries, view.case(), &catalog, &hash, index, cancel)?,
            query => graph(&queries, view.case(), &catalog, query, cancel)?,
        };
        check(cancel)?;
        Ok(with_coverage(result, coverage, incomplete))
    }
}

fn with_coverage(
    result: TaskEvidenceResult,
    coverage: Option<&str>,
    incomplete: bool,
) -> TaskEvidenceResult {
    let notice = coverage.unwrap_or("");
    let prefix = |text: String| {
        if notice.is_empty() {
            text
        } else {
            format!("{notice}\n{text}")
        }
    };
    match result {
        TaskEvidenceResult::Text(text) if incomplete => TaskEvidenceResult::PartialText {
            text: prefix(text),
            reason: TaskQueryPartialReason::Coverage,
        },
        TaskEvidenceResult::Text(text) => TaskEvidenceResult::Text(prefix(text)),
        TaskEvidenceResult::PartialText { text, reason } => TaskEvidenceResult::PartialText {
            text: prefix(text),
            reason,
        },
        TaskEvidenceResult::Timeline(events) if incomplete => TaskEvidenceResult::PartialTimeline {
            events,
            reason: TaskQueryPartialReason::Coverage,
        },
        result => result,
    }
}

fn graph(
    queries: &crate::parquet_store::QueryStore<'_>,
    id: &irmind_domain::CaseId,
    catalog: &crate::graph_port::QueryCatalog,
    query: TaskEvidenceQuery,
    cancel: &CancellationToken,
) -> Result<TaskEvidenceResult, AppError> {
    let text = match query {
        TaskEvidenceQuery::GraphSummary => queries.summary_answer(id, catalog, cancel)?,
        TaskEvidenceQuery::EntityLookup {
            filter,
            kind,
            value,
        } => queries.entity_answer(id, catalog, &filter, &kind, &value, cancel)?,
        TaskEvidenceQuery::Neighbors {
            filter,
            kind,
            value,
            limit,
        } => queries.neighbors_answer(id, catalog, &filter, (&kind, &value), limit, cancel)?,
        TaskEvidenceQuery::Timeline {
            filter,
            entity: Some((kind, value)),
            limit,
        } => {
            queries.entity_timeline_answer(id, catalog, &filter, (&kind, &value), limit, cancel)?
        }
        TaskEvidenceQuery::Timeline {
            filter,
            entity: None,
            limit,
        } => {
            let answer = queries.timeline_answer(id, catalog, &filter, limit, cancel)?;
            return Ok(match answer.reason {
                Some(reason) => TaskEvidenceResult::PartialTimeline {
                    events: answer.value,
                    reason,
                },
                None => TaskEvidenceResult::Timeline(answer.value),
            });
        }
        TaskEvidenceQuery::Path { filter, from, to } => queries.path_answer(
            id,
            catalog,
            &filter,
            (&from.0, &from.1),
            (&to.0, &to.1),
            cancel,
        )?,
        TaskEvidenceQuery::TextSearch {
            filter,
            query,
            limit,
        } => queries.search_answer(id, catalog, &filter, &query, limit, cancel)?,
        _ => return Err(invalid()),
    };
    Ok(match text.reason {
        Some(reason) => TaskEvidenceResult::PartialText {
            text: text.value,
            reason,
        },
        None => TaskEvidenceResult::Text(text.value),
    })
}
fn raw(
    queries: &crate::parquet_store::QueryStore<'_>,
    id: &irmind_domain::CaseId,
    catalog: &crate::graph_port::QueryCatalog,
    hash: &irmind_domain::EvidenceHash,
    index: u64,
    cancel: &CancellationToken,
) -> Result<TaskEvidenceResult, AppError> {
    let raw = queries
        .raw_native(
            id,
            catalog,
            hash.as_str(),
            usize::try_from(index).map_err(|_| invalid())?,
            cancel,
        )?
        .ok_or_else(invalid)?;
    let excerpt = raw.chars().take(2_000).collect::<String>();
    let suffix = if excerpt.len() < raw.len() {
        " [truncated]"
    } else {
        ""
    };
    let text = format!(
        "view=indexed source={}#{index} {excerpt}{suffix}",
        hash.as_str()
    );
    Ok(if excerpt.len() < raw.len() {
        TaskEvidenceResult::PartialText {
            text,
            reason: TaskQueryPartialReason::ExcerptLimit,
        }
    } else {
        TaskEvidenceResult::Text(text)
    })
}
impl TaskQueries {
    fn incomplete_coverage(
        &self,
        view: &VerifiedTaskQueryView,
        classifications: bool,
        cancel: &CancellationToken,
    ) -> Result<bool, AppError> {
        for entry in self
            .store
            .entries(view.case())?
            .into_iter()
            .take_while(|entry| entry.seq <= view.generation_seq())
        {
            check(cancel)?;
            if entry.kind == irmind_domain::AuditEventKind::SourceManifestV2 {
                let manifest = irmind_domain::SourceManifestV2::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if view.sources().contains(manifest.source.sha256.as_str())
                    && manifest.rejected_records != 0
                {
                    return Ok(true);
                }
            } else if classifications && entry.kind == irmind_domain::AuditEventKind::MappingRunV1 {
                let run = irmind_domain::MappingRunV1::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if run.routes().iter().any(|route| {
                    view.sources().contains(route.source().as_str())
                        && route.counts().unclassified() != 0
                }) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn search(
        &self,
        view: &VerifiedTaskQueryView,
        query: &str,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        let mut result = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let query_lower = query.to_ascii_lowercase();
        // Filter the hash inventory before reads, snippets, ordering or top-N.
        for hash in self
            .store
            .evidence_hashes(view.case())?
            .into_iter()
            .filter(|hash| view.sources().contains(hash))
        {
            check(cancel)?;
            if Instant::now() >= deadline {
                return Ok(TaskEvidenceResult::PartialText {
                    text: result.join("\n"),
                    reason: TaskQueryPartialReason::Deadline,
                });
            }
            let bytes = self.store.get_evidence(view.case(), &hash)?;
            let text = String::from_utf8_lossy(&bytes);
            if let Some(offset) = text.to_ascii_lowercase().find(&query_lower) {
                let start = text.floor_char_boundary(offset.saturating_sub(80));
                let end = text.ceil_char_boundary((offset + query.len() + 80).min(text.len()));
                result.push(format!("{hash}: {}", &text[start..end]));
                if result.len() == limit {
                    break;
                }
            }
        }
        Ok(TaskEvidenceResult::Text(result.join("\n")))
    }
}
fn check(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        Err(AppError::Cancelled)
    } else {
        Ok(())
    }
}
fn invalid() -> AppError {
    AppError::Policy("record pointer is not in the task's signed source view".into())
}
