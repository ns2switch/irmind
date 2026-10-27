use crate::{
    AppError, AuthorizedCall, CancellationToken, CaseId, Engine, Provenance, SourceKind, Tainted,
    Tool, hex, sha256,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphRecord {
    pub index: usize,
    pub at: String,
    pub event: String,
    pub text: String,
    pub entities: Vec<(String, String)>,
    pub relations: Vec<GraphRelation>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GraphRelation {
    pub from_kind: String,
    pub from_value: String,
    pub relation: String,
    pub to_kind: String,
    pub to_value: String,
}

#[derive(Clone, Debug)]
pub struct TimelineEvent {
    pub at: String,
    pub event: String,
    pub evidence_hash: String,
    pub record_index: usize,
}

impl Engine<'_> {
    pub fn ingest(&self, id: &CaseId, bytes: &[u8], source: &str) -> Result<String, AppError> {
        self.ingest_cancelable(id, bytes, source, &CancellationToken::new())
    }

    pub fn ingest_cancelable(
        &self,
        id: &CaseId,
        bytes: &[u8],
        source: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let _tainted = Tainted::from_external(
            bytes,
            Provenance::new(sha256(bytes), None, SourceKind::File),
        );
        self.require_attended_analyst("ingest evidence")?;
        let _case_lock = self.repo.lock_case(id)?;
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        if bytes.len() > 50_000_000 {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyEvidenceExceeds50MB,
            ));
        }
        if source.is_empty()
            || source.len() > 1000
            || source.starts_with('/')
            || source.contains('\\')
            || source.contains(':')
            || source
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicySourceMustBeARelativeSlashSeparatedPath,
            ));
        }
        let hash = hex(&sha256(bytes));
        self.evidence_store.put_evidence(id, &hash, bytes)?;
        self.audit(
            id,
            crate::AuditOrigin::System,
            irmind_domain::AuditEventKind::EvidenceIngested,
            source,
            Some(&hash),
        )?;
        for chunk in bytes.chunks(250_000) {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            self.screen_and_audit(
                id,
                &String::from_utf8_lossy(chunk),
                "IngestedEvidence",
                Some(&hash),
            )?;
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let records = self.parser.parse(source, bytes)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.graph.index_records(id, &hash, &records, cancel)?;
        self.audit(
            id,
            crate::AuditOrigin::System,
            irmind_domain::AuditEventKind::GraphIndexed,
            &format!(
                "parser={};graph={};records={}",
                self.parser.version(),
                self.graph.graph_version(),
                records.len()
            ),
            Some(&hash),
        )?;
        Ok(hash)
    }

    pub(crate) fn index_remote_result(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        hash: &str,
        raw: &[u8],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if !matches!(
            call.tool(),
            Tool::SiemSearch
                | Tool::CloudAuditEvents
                | Tool::EdrHostInfo
                | Tool::EdrProcessTree
                | Tool::EdrDetections
        ) {
            return Ok(());
        }
        let source = format!(
            "{}:{}",
            call.tool().as_str(),
            call.arg("source").unwrap_or("unknown")
        );
        let records = self.parser.parse(&source, raw)?;
        self.graph.index_records(id, hash, &records, cancel)?;
        self.audit(
            id,
            crate::AuditOrigin::System,
            irmind_domain::AuditEventKind::GraphIndexed,
            &format!(
                "parser={};graph={};records={}",
                self.parser.version(),
                self.graph.graph_version(),
                records.len()
            ),
            Some(hash),
        )
    }

    pub fn rebuild_graph(&self, id: &CaseId) -> Result<usize, AppError> {
        self.rebuild_graph_cancelable(id, &CancellationToken::new())
    }

    pub fn rebuild_graph_cancelable(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        self.require_attended_analyst("rebuild graph")?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked_cancelable(id, cancel)?;
        let sources = self.graph_sources(id)?;
        self.graph
            .rebuild_graph(id, &sources, self.parser.as_ref(), cancel)
    }

    pub fn verify_graph(&self, id: &CaseId) -> Result<usize, AppError> {
        self.verify_graph_cancelable(id, &CancellationToken::new())
    }

    pub fn verify_graph_cancelable(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked_cancelable(id, cancel)?;
        let sources = self.graph_sources(id)?;
        self.graph
            .verify_graph(id, &sources, self.parser.as_ref(), cancel)
    }

    pub(crate) fn graph_sources(&self, id: &CaseId) -> Result<Vec<(String, usize)>, AppError> {
        let mut sources = std::collections::BTreeMap::new();
        for entry in self.audit_log.entries(id)? {
            if entry.kind != irmind_domain::AuditEventKind::GraphIndexed {
                continue;
            }
            let hash = entry.evidence.ok_or(AppError::InvalidChain(entry.seq))?;
            let parts = entry.payload.split(';').collect::<Vec<_>>();
            if parts.len() != 3
                || !matches!(
                    parts[0],
                    "parser=json-cloudtrail-v1"
                        | "parser=json-cloudtrail-v2"
                        | "parser=json-cloudtrail-v3"
                        | "parser=json-cloudtrail-v4"
                )
                || !matches!(
                    parts[1],
                    "graph=duckdb-graph-v1" | "graph=duckdb-graph-v2" | "graph=duckdb-graph-v3"
                )
            {
                return Err(AppError::Policy(format!(
                    "unsupported graph parser or version at audit sequence {}",
                    entry.seq
                )));
            }
            let count = parts[2]
                .strip_prefix("records=")
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(AppError::InvalidChain(entry.seq))?;
            if let Some(existing) = sources.insert(hash, count)
                && existing != count
            {
                return Err(AppError::InvalidChain(entry.seq));
            }
        }
        Ok(sources.into_iter().collect())
    }
}
