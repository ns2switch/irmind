use crate::{
    AppError, AuditLog, CaseId, EvidenceGraph, LocalStore, Repository, TimelineEvent, storage,
    storage_reason,
};
use irmind_app::CancellationToken;
use irmind_domain::{CaseScope, GraphQueryFilter, ParquetArtifact};

struct QueryCatalog {
    artifacts: Vec<ParquetArtifact>,
    source_names: std::collections::BTreeMap<String, String>,
}
impl std::ops::Deref for QueryCatalog {
    type Target = [ParquetArtifact];
    fn deref(&self) -> &Self::Target {
        &self.artifacts
    }
}
mod catalog;
pub(crate) use catalog::CachedCatalog;

impl EvidenceGraph for LocalStore {
    fn graph_version(&self) -> &'static str {
        "parquet-graph-v1"
    }

    fn graph_summary(&self, id: &CaseId) -> Result<String, AppError> {
        let artifacts = self.query_artifacts(id, &GraphQueryFilter::default())?;
        self.parquet
            .queries(&artifacts.source_names)
            .summary_native(id, &artifacts, &CancellationToken::new())
    }

    fn timeline_filtered(
        &self,
        id: &CaseId,
        filter: &GraphQueryFilter,
        limit: usize,
    ) -> Result<Vec<TimelineEvent>, AppError> {
        let artifacts = self.query_artifacts(id, filter)?;
        self.parquet
            .queries(&artifacts.source_names)
            .timeline_native(id, &artifacts, filter, limit, &CancellationToken::new())
    }

    fn entity_lookup_filtered(
        &self,
        id: &CaseId,
        filter: &GraphQueryFilter,
        kind: &str,
        value: &str,
    ) -> Result<String, AppError> {
        self.check_entity_query(id, kind, value, 1)?;
        let artifacts = self.query_artifacts(id, filter)?;
        self.parquet
            .queries(&artifacts.source_names)
            .entity_native(
                id,
                &artifacts,
                filter,
                kind,
                value,
                &CancellationToken::new(),
            )
            .map(|output| with_coverage(filter, output))
    }

    fn neighbors_filtered(
        &self,
        id: &CaseId,
        filter: &GraphQueryFilter,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<String, AppError> {
        self.check_entity_query(id, kind, value, limit)?;
        let artifacts = self.query_artifacts(id, filter)?;
        self.parquet
            .queries(&artifacts.source_names)
            .neighbors_native(
                id,
                &artifacts,
                filter,
                (kind, value),
                limit,
                &CancellationToken::new(),
            )
            .map(|output| with_coverage(filter, output))
    }

    fn entity_timeline_filtered(
        &self,
        id: &CaseId,
        filter: &GraphQueryFilter,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<String, AppError> {
        self.check_entity_query(id, kind, value, limit)?;
        let artifacts = self.query_artifacts(id, filter)?;
        self.parquet
            .queries(&artifacts.source_names)
            .entity_timeline_native(
                id,
                &artifacts,
                filter,
                (kind, value),
                limit,
                &CancellationToken::new(),
            )
            .map(|output| with_coverage(filter, output))
    }

    fn graph_path_filtered(
        &self,
        id: &CaseId,
        filter: &GraphQueryFilter,
        from: (&str, &str),
        to: (&str, &str),
    ) -> Result<String, AppError> {
        self.check_entity_query(id, from.0, from.1, 1)?;
        self.check_entity_query(id, to.0, to.1, 1)?;
        let artifacts = self.query_artifacts(id, filter)?;
        self.parquet
            .queries(&artifacts.source_names)
            .path_native(id, &artifacts, filter, from, to, &CancellationToken::new())
            .map(|output| with_coverage(filter, output))
    }

    fn text_search_filtered(
        &self,
        id: &CaseId,
        filter: &GraphQueryFilter,
        query: &str,
        limit: usize,
    ) -> Result<String, AppError> {
        self.get_case(id)?;
        if query.trim().is_empty() || query.len() > 128 || !(1..=20).contains(&limit) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidTextSearchArguments,
            )));
        }
        let artifacts = self.query_artifacts(id, filter)?;
        self.parquet
            .queries(&artifacts.source_names)
            .search_native(
                id,
                &artifacts,
                filter,
                query,
                limit,
                &CancellationToken::new(),
            )
            .map(|output| with_coverage(filter, output))
    }

    fn raw_record(&self, id: &CaseId, hash: &str, index: usize) -> Result<String, AppError> {
        self.get_case(id)?;
        if hash.len() != 64
            || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            || index >= 100_000
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidRawRecordPointer,
            )));
        }
        let hash = hash.to_ascii_lowercase();
        let artifacts = self.query_catalog(id)?;
        if artifacts.iter().any(|item| {
            item.source_hashes()
                .iter()
                .any(|source| source.as_str() == hash)
        }) {
            let raw = self
                .parquet
                .queries(&artifacts.source_names)
                .raw_native(id, &artifacts, &hash, index, &CancellationToken::new())?
                .ok_or_else(|| storage_reason("record pointer missing from signed Parquet"))?;
            return Ok(format_raw(&hash, index, &raw));
        }
        Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::RecordPointerIsNotIndexedInThisCase,
        )))
    }
}

fn format_raw(hash: &str, index: usize, raw: &str) -> String {
    let excerpt = raw.chars().take(2_000).collect::<String>();
    let suffix = if raw.chars().count() > 2_000 {
        " [truncated]"
    } else {
        ""
    };
    format!("source={hash}#{index} {excerpt}{suffix}")
}

impl LocalStore {
    fn query_artifacts(
        &self,
        id: &CaseId,
        filter: &GraphQueryFilter,
    ) -> Result<QueryCatalog, AppError> {
        let case = self.get_case(id)?;
        let scope = CaseScope::parse(&case.scope)
            .map_err(|_| AppError::Policy("invalid case scope".into()))?;
        if !filter.within_scope(&scope) {
            return Err(AppError::Policy("graph filter outside case scope".into()));
        }
        self.query_catalog(id)
    }

    fn check_entity_query(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<(), AppError> {
        self.get_case(id)?;
        if !irmind_domain::valid_entity(kind, value) || !(1..=20).contains(&limit) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidGraphQueryArguments,
            )));
        }
        Ok(())
    }
}

fn with_coverage(filter: &GraphQueryFilter, output: String) -> String {
    match filter.coverage_notice() {
        Some(notice) => format!("{notice}\n{output}"),
        None => output,
    }
}
