use crate::{
    AppError, CaseId, EventParser, EvidenceGraph, EvidenceStore, GraphRecord, LocalStore,
    Repository, Tainted, TimelineEvent, Value, storage, storage_reason,
};

impl EvidenceGraph for LocalStore {
    fn index_records(
        &self,
        id: &CaseId,
        hash: &str,
        records: &[Tainted<GraphRecord>],
        cancel: &irmind_app::CancellationToken,
    ) -> Result<(), AppError> {
        self.graph.index_records(id, hash, records, cancel)
    }

    fn graph_version(&self) -> &'static str {
        "duckdb-graph-v3"
    }

    fn graph_summary(&self, id: &CaseId) -> Result<String, AppError> {
        self.graph.summary(id)
    }

    fn timeline(&self, id: &CaseId, limit: usize) -> Result<Vec<TimelineEvent>, AppError> {
        self.graph.timeline(id, limit)
    }

    fn entity_lookup(&self, id: &CaseId, kind: &str, value: &str) -> Result<String, AppError> {
        self.check_entity_query(id, kind, value, 1)?;
        self.graph.entity_lookup(id, kind, value)
    }

    fn neighbors(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<String, AppError> {
        self.check_entity_query(id, kind, value, limit)?;
        self.graph.neighbors(id, kind, value, limit)
    }

    fn entity_timeline(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<String, AppError> {
        self.check_entity_query(id, kind, value, limit)?;
        self.graph.entity_timeline(id, kind, value, limit)
    }

    fn graph_path(
        &self,
        id: &CaseId,
        from: (&str, &str),
        to: (&str, &str),
    ) -> Result<String, AppError> {
        self.check_entity_query(id, from.0, from.1, 1)?;
        self.check_entity_query(id, to.0, to.1, 1)?;
        self.graph.path(id, from, to)
    }

    fn text_search(&self, id: &CaseId, query: &str, limit: usize) -> Result<String, AppError> {
        self.get_case(id)?;
        if query.trim().is_empty() || query.len() > 128 || !(1..=20).contains(&limit) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidTextSearchArguments,
            )));
        }
        self.graph.text_search(id, query, limit)
    }

    fn raw_record(&self, id: &CaseId, hash: &str, index: usize) -> Result<String, AppError> {
        self.get_case(id)?;
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) || index >= 100_000 {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidRawRecordPointer,
            )));
        }
        let hash = hash.to_ascii_lowercase();
        if !self.graph.has_record(id, &hash, index)? {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::RecordPointerIsNotIndexedInThisCase,
            )));
        }
        let bytes = self.get_evidence(id, &hash)?;
        let parsed: Result<Value, _> = serde_json::from_slice(&bytes);
        let record = match parsed {
            Ok(Value::Array(items)) => items.get(index).cloned(),
            Ok(Value::Object(object)) => match object.get("Records") {
                Some(Value::Array(items)) => items.get(index).cloned(),
                _ => match object.get("events") {
                    Some(Value::Array(items)) => items.get(index).cloned(),
                    _ if index == 0 => Some(Value::Object(object)),
                    _ => None,
                },
            },
            Ok(_) => None,
            Err(_) => bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
                .nth(index)
                .map(serde_json::from_slice::<Value>)
                .transpose()
                .map_err(storage)?,
        }
        .ok_or_else(|| storage_reason("indexed record missing from source evidence"))?;
        let encoded = serde_json::to_string(&record).map_err(storage)?;
        let excerpt: String = encoded.chars().take(2_000).collect();
        let suffix = if encoded.chars().count() > 2_000 {
            " [truncated]"
        } else {
            ""
        };
        Ok(format!("source={hash}#{index} {excerpt}{suffix}"))
    }

    fn rebuild_graph(
        &self,
        id: &CaseId,
        sources: &[(String, usize)],
        parser: &dyn EventParser,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<usize, AppError> {
        self.get_case(id)?;
        self.graph.rebuild(id, sources, cancel, |hash| {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let bytes = self.get_evidence(id, hash)?;
            parser.parse("rebuild", &bytes)
        })
    }

    fn verify_graph(
        &self,
        id: &CaseId,
        sources: &[(String, usize)],
        parser: &dyn EventParser,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<usize, AppError> {
        self.get_case(id)?;
        self.graph.verify(id, sources, cancel, |hash| {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let bytes = self.get_evidence(id, hash)?;
            parser.parse("verify", &bytes)
        })
    }
}
