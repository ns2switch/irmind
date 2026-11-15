use super::SubagentDigest;
use crate::{AppError, CancellationToken, CaseId, CaseScope, GraphQueryFilter, TimelineEvent};
use irmind_domain::{EvidenceHash, SourceRecordV1, Tainted};
use std::collections::BTreeSet;

pub(super) fn scope_text(scope: &CaseScope) -> Result<String, super::SubagentRecordError> {
    match scope {
        CaseScope::LocalOnly => Ok("local".into()),
        CaseScope::Remote { .. } => scope
            .to_current_string()
            .map_err(|_| super::SubagentRecordError),
    }
}

/// A broker-created frozen query generation, never a model argument.
/// It does not authorize a tool dispatch, remote read, approval or source root.
pub struct VerifiedTaskQueryView {
    pub(super) case: CaseId,
    pub(super) task: SubagentDigest,
    pub(super) generation_seq: u64,
    pub(super) generation_hash: SubagentDigest,
    pub(super) source_set: SubagentDigest,
    pub(super) sources: BTreeSet<String>,
    pub(super) scope: CaseScope,
    pub(super) ceiling: Option<CaseScope>,
    pub(super) policy_fingerprint: SubagentDigest,
}
impl VerifiedTaskQueryView {
    pub const fn case(&self) -> &CaseId {
        &self.case
    }
    pub const fn task(&self) -> SubagentDigest {
        self.task
    }
    pub const fn generation_seq(&self) -> u64 {
        self.generation_seq
    }
    pub const fn generation_hash(&self) -> SubagentDigest {
        self.generation_hash
    }
    pub const fn source_set(&self) -> SubagentDigest {
        self.source_set
    }
    pub fn sources(&self) -> &BTreeSet<String> {
        &self.sources
    }
    pub const fn policy_fingerprint(&self) -> SubagentDigest {
        self.policy_fingerprint
    }
    pub fn permits_filter(&self, filter: &GraphQueryFilter) -> bool {
        filter.within_scope(&self.scope)
            && self
                .ceiling
                .as_ref()
                .is_none_or(|scope| filter.within_scope(scope))
    }
}

/// The same bounded local queries, with an additional mandatory source view.
/// Original reads retain the separately authorized `SourceEvidenceReader` path.
pub enum TaskEvidenceQuery {
    EvidenceSearch {
        query: String,
        limit: usize,
    },
    EvidenceRead {
        hash: EvidenceHash,
        limit: usize,
    },
    GraphSummary,
    EntityLookup {
        filter: GraphQueryFilter,
        kind: String,
        value: String,
    },
    Neighbors {
        filter: GraphQueryFilter,
        kind: String,
        value: String,
        limit: usize,
    },
    Timeline {
        filter: GraphQueryFilter,
        entity: Option<(String, String)>,
        limit: usize,
    },
    Path {
        filter: GraphQueryFilter,
        from: (String, String),
        to: (String, String),
    },
    TextSearch {
        filter: GraphQueryFilter,
        query: String,
        limit: usize,
    },
    RawRecords {
        hash: EvidenceHash,
        index: u64,
        original: bool,
    },
}
impl TaskEvidenceQuery {
    pub fn filter(&self) -> Option<&GraphQueryFilter> {
        match self {
            Self::EntityLookup { filter, .. }
            | Self::Neighbors { filter, .. }
            | Self::Timeline { filter, .. }
            | Self::Path { filter, .. }
            | Self::TextSearch { filter, .. } => Some(filter),
            _ => None,
        }
    }
    pub fn validate(&self, view: &VerifiedTaskQueryView) -> Result<(), AppError> {
        if self
            .filter()
            .is_some_and(|filter| !view.permits_filter(filter))
        {
            return Err(unsupported());
        }
        let valid = match self {
            Self::EvidenceSearch { query, limit } | Self::TextSearch { query, limit, .. } => {
                !query.trim().is_empty() && query.len() <= 128 && (1..=20).contains(limit)
            }
            Self::EvidenceRead { hash, limit } => {
                view.sources.contains(hash.as_str()) && (1..=20).contains(limit)
            }
            Self::RawRecords { hash, index, .. } => {
                view.sources.contains(hash.as_str()) && *index < 100_000
            }
            Self::EntityLookup { kind, value, .. } => irmind_domain::valid_entity(kind, value),
            Self::Neighbors {
                kind, value, limit, ..
            } => irmind_domain::valid_entity(kind, value) && (1..=20).contains(limit),
            Self::Timeline { entity, limit, .. } => {
                (1..=20).contains(limit)
                    && entity
                        .as_ref()
                        .is_none_or(|(kind, value)| irmind_domain::valid_entity(kind, value))
            }
            Self::Path { from, to, .. } => {
                irmind_domain::valid_entity(&from.0, &from.1)
                    && irmind_domain::valid_entity(&to.0, &to.1)
            }
            Self::GraphSummary => true,
        };
        if valid { Ok(()) } else { Err(unsupported()) }
    }
}

/// Untrusted adapter data: screen it before exposing it to any model or UI.
pub enum TaskEvidenceResult {
    Text(String),
    Timeline(Vec<TimelineEvent>),
    Original(Box<Tainted<SourceRecordV1>>),
}
pub trait TaskEvidenceQueries: Send + Sync {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        cancel: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError>;
}
pub(super) fn unsupported() -> AppError {
    AppError::Policy("TaskSourceViewUnsupported: restricted task query is unavailable; no unrestricted fallback was used".into())
}

#[cfg(test)]
#[path = "query_tests.rs"]
#[allow(clippy::unwrap_used)]
mod tests;
