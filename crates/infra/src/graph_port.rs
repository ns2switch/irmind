use crate::{
    AppError, AuditLog, CaseId, EventParser, EvidenceGraph, LocalStore, Repository, Tainted,
    TimelineEvent, storage, storage_reason,
};
use irmind_app::{CancellationToken, GraphRecord};
use irmind_domain::{CaseScope, GraphQueryFilter, ParquetArtifactV1};

mod catalog;
pub(crate) use catalog::CachedCatalog;

impl EvidenceGraph for LocalStore {
    fn index_from_parser(
        &self,
        _id: &CaseId,
        _hash: &str,
        _source: &str,
        _bytes: &[u8],
        _parser: &dyn EventParser,
        _cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        Err(retired_index())
    }

    fn index_records(
        &self,
        _id: &CaseId,
        _hash: &str,
        _records: &[Tainted<GraphRecord>],
        _cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        Err(retired_index())
    }

    fn graph_version(&self) -> &'static str {
        "parquet-graph-v1"
    }

    fn graph_summary(&self, id: &CaseId) -> Result<String, AppError> {
        let artifacts = self.query_artifacts(id, &GraphQueryFilter::default())?;
        self.parquet
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
        self.parquet.entity_native(
            id,
            &artifacts,
            filter,
            kind,
            value,
            &CancellationToken::new(),
        )
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
        self.parquet.neighbors_native(
            id,
            &artifacts,
            filter,
            (kind, value),
            limit,
            &CancellationToken::new(),
        )
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
        self.parquet.entity_timeline_native(
            id,
            &artifacts,
            filter,
            (kind, value),
            limit,
            &CancellationToken::new(),
        )
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
            .path_native(id, &artifacts, filter, from, to, &CancellationToken::new())
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
        self.parquet.search_native(
            id,
            &artifacts,
            filter,
            query,
            limit,
            &CancellationToken::new(),
        )
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
        if let Some(artifacts) = self.signed_parquet_artifacts(id)?
            && artifacts.iter().any(|item| {
                item.source_hashes
                    .iter()
                    .any(|source| source.as_str() == hash)
            })
        {
            let raw = self
                .parquet
                .raw_native(id, &artifacts, &hash, index, &CancellationToken::new())?
                .ok_or_else(|| storage_reason("record pointer missing from signed Parquet"))?;
            return Ok(format_raw(&hash, index, &raw));
        }
        Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::RecordPointerIsNotIndexedInThisCase,
        )))
    }

    fn rebuild_graph(
        &self,
        _id: &CaseId,
        _sources: &[(String, usize)],
        _parser: &dyn EventParser,
        _cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        Err(retired_index())
    }

    fn verify_graph(
        &self,
        _id: &CaseId,
        _sources: &[(String, usize)],
        _parser: &dyn EventParser,
        _cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        Err(retired_index())
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

fn retired_index() -> AppError {
    AppError::Policy("the old graph index is retired; ingest through the signed Parquet use case or run /migrate".into())
}

impl LocalStore {
    fn query_artifacts(
        &self,
        id: &CaseId,
        filter: &GraphQueryFilter,
    ) -> Result<Vec<ParquetArtifactV1>, AppError> {
        let case = self.get_case(id)?;
        let scope = CaseScope::parse(&case.scope)
            .map_err(|_| AppError::Policy("invalid case scope".into()))?;
        if !filter.within_scope(&scope) {
            return Err(AppError::Policy("graph filter outside case scope".into()));
        }
        let artifacts = self.signed_parquet_artifacts(id)?;
        if self.has_legacy_graph(id)? {
            return Err(AppError::Policy("derived graph is unavailable until legacy evidence is migrated to Parquet; the signed case chain remains accessible".into()));
        }
        Ok(artifacts.unwrap_or_default())
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
