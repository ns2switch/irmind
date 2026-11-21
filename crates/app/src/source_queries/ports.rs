use super::{
    CompiledSourceQueryV1, QUERY_MAX_PAGES, QueryAccounting, QueryTime, ResolvedQuerySourceV1,
    SourceQueryError, SourceQueryLimits, SourceQueryModuleV1, SourceQueryV1,
};
use crate::{AppError, AuthorizedCall, CancellationToken, async_trait};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryPreflightV1 {
    pub plan_digest: String,
    pub observed_at: QueryTime,
    pub accounting: QueryAccounting,
    pub estimate: QueryEstimate,
    pub provider_ceiling: Option<u64>,
    pub source_metadata: Value,
    pub uncertainty: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryEstimate {
    pub unit: String,
    pub value: Option<u64>,
    pub basis: String,
    pub reliable: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryUsage {
    pub scanned_bytes: Option<u64>,
    pub processed_bytes: Option<u64>,
    pub billed_bytes: Option<u64>,
    pub returned_wire_bytes: u64,
    pub returned_decoded_bytes: u64,
    pub query_price_basis: QueryAccounting,
}
#[derive(Clone, Debug)]
pub enum SubmitObservationV1 {
    Accepted(QueryExecutionRef),
    NotSubmitted,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryExecutionRef {
    plan: String,
    attempt: u64,
    provider_id: String,
}
impl QueryExecutionRef {
    pub fn new(plan: &str, attempt: u64, provider_id: &str) -> Result<Self, SourceQueryError> {
        if !super::types::digest(plan) || attempt == 0 || !super::types::text(provider_id, 1024) {
            return Err(SourceQueryError::Invalid);
        }
        Ok(Self {
            plan: plan.into(),
            attempt,
            provider_id: provider_id.into(),
        })
    }
    pub fn plan(&self) -> &str {
        &self.plan
    }
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
}
#[derive(Clone, Debug)]
pub enum QueryExecutionStatus {
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
    Unknown,
    Unsupported,
}
#[derive(Clone, Debug)]
pub struct ExecutionObservationV1 {
    pub status: QueryExecutionStatus,
    pub request_id: Option<String>,
    pub usage: SourceQueryUsage,
    pub source_observation: Option<Value>,
}
#[derive(Clone, Debug)]
pub enum CancelObservationV1 {
    Requested,
    Terminal,
    Unsupported,
    Unknown,
}
pub struct QueryResultCursor {
    execution: QueryExecutionRef,
    ordinal: u64,
    token: Option<String>,
    token_hashes: BTreeSet<[u8; 32]>,
}
impl std::fmt::Debug for QueryResultCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueryResultCursor")
            .field("ordinal", &self.ordinal)
            .finish_non_exhaustive()
    }
}
impl QueryResultCursor {
    pub fn first(execution: &QueryExecutionRef) -> Self {
        Self {
            execution: execution.clone(),
            ordinal: 0,
            token: None,
            token_hashes: BTreeSet::new(),
        }
    }
    pub fn next(
        mut self,
        execution: &QueryExecutionRef,
        token: &str,
    ) -> Result<Self, SourceQueryError> {
        if self.execution != *execution
            || self.ordinal + 1 >= QUERY_MAX_PAGES
            || token.is_empty()
            || token.len() > 4096
            || !self.token_hashes.insert(crate::sha256(token.as_bytes()))
        {
            return Err(SourceQueryError::Invalid);
        }
        self.ordinal += 1;
        self.token = Some(token.into());
        Ok(self)
    }
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }
    pub fn check(&self, execution: &QueryExecutionRef) -> Result<(), SourceQueryError> {
        if self.execution == *execution {
            Ok(())
        } else {
            Err(SourceQueryError::Invalid)
        }
    }
}
pub struct QueryResponsePage {
    pub request_id: Option<String>,
    pub next_token: Option<String>,
    pub content_encoding: String,
    pub chunks: crate::ObjectStream,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceQueryLeasePhase {
    Submit,
    Reconcile,
    Fetch,
    Cancel,
}

/// Unforgeable lease. Only the verified broker can construct it.
pub struct AdmittedSourceQuery {
    pub(super) case_id: crate::CaseId,
    pub(super) plan: String,
    pub(super) attempt: u64,
    pub(super) reservation: String,
    pub(super) source: ResolvedQuerySourceV1,
    pub(super) compiled: CompiledSourceQueryV1,
    pub(super) limits: SourceQueryLimits,
    pub(super) execution_key: String,
    pub(super) phase: SourceQueryLeasePhase,
    pub(super) execution: Option<QueryExecutionRef>,
}
impl AdmittedSourceQuery {
    pub fn case_id(&self) -> &crate::CaseId {
        &self.case_id
    }
    pub fn plan(&self) -> &str {
        &self.plan
    }
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }
    pub fn reservation(&self) -> &str {
        &self.reservation
    }
    pub fn source(&self) -> &ResolvedQuerySourceV1 {
        &self.source
    }
    pub fn compiled(&self) -> &CompiledSourceQueryV1 {
        &self.compiled
    }
    pub fn limits(&self) -> &SourceQueryLimits {
        &self.limits
    }
    pub fn execution_key(&self) -> &str {
        &self.execution_key
    }
    /// Adapters check this before every request, including polls and retries.
    pub fn check(
        &self,
        module: &str,
        source: &str,
        phase: SourceQueryLeasePhase,
        execution: Option<&QueryExecutionRef>,
    ) -> Result<(), SourceQueryError> {
        if self.source.module() == module
            && self.source.id() == source
            && self.phase == phase
            && self.execution.as_ref() == execution
            && execution.is_none_or(|job| job.plan() == self.plan)
        {
            Ok(())
        } else {
            Err(SourceQueryError::Scope)
        }
    }
}
#[async_trait]
pub trait SourceQueryExecutor: Send + Sync {
    fn descriptor(&self) -> SourceQueryModuleV1;
    fn compile(
        &self,
        source: &ResolvedQuerySourceV1,
        query: &SourceQueryV1,
    ) -> Result<CompiledSourceQueryV1, AppError>;
    async fn preflight(
        &self,
        call: &AuthorizedCall,
        query: &CompiledSourceQueryV1,
        cancel: &CancellationToken,
    ) -> Result<QueryPreflightV1, AppError>;
    async fn submit(
        &self,
        lease: &AdmittedSourceQuery,
        cancel: &CancellationToken,
    ) -> Result<SubmitObservationV1, AppError>;
    async fn reconcile(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cancel: &CancellationToken,
    ) -> Result<ExecutionObservationV1, AppError>;
    async fn fetch(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cursor: &QueryResultCursor,
        cancel: &CancellationToken,
    ) -> Result<QueryResponsePage, AppError>;
    async fn cancel(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cancel: &CancellationToken,
    ) -> Result<CancelObservationV1, AppError>;
}
#[derive(Default)]
pub struct SourceQueryPorts {
    executors: BTreeMap<String, Arc<dyn SourceQueryExecutor>>,
    page_decoders: BTreeMap<(String, String, String), Arc<dyn super::SourceQueryPageDecoder>>,
}
impl SourceQueryPorts {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, executor: Arc<dyn SourceQueryExecutor>) -> Result<(), SourceQueryError> {
        let descriptor = executor.descriptor();
        descriptor.validate()?;
        if self.executors.contains_key(&descriptor.id) {
            return Err(SourceQueryError::Invalid);
        }
        self.executors.insert(descriptor.id, executor);
        Ok(())
    }
    pub fn add_page_decoder(
        &mut self,
        module: &str,
        version: &str,
        dataset: &str,
        decoder: Arc<dyn super::SourceQueryPageDecoder>,
    ) -> Result<(), SourceQueryError> {
        let descriptor = self.executor(module)?.descriptor();
        let identity = decoder.identity();
        irmind_domain::SourceDecoderIdentityV1::try_new(identity.name, identity.version)
            .map_err(|_| SourceQueryError::Invalid)?;
        let key = (module.into(), version.into(), dataset.into());
        if descriptor.version != version
            || !descriptor.datasets.iter().any(|name| name == dataset)
            || self.page_decoders.contains_key(&key)
        {
            return Err(SourceQueryError::Invalid);
        }
        self.page_decoders.insert(key, decoder);
        Ok(())
    }

    pub fn page_decoder(
        &self,
        source: &ResolvedQuerySourceV1,
    ) -> Result<&dyn super::SourceQueryPageDecoder, SourceQueryError> {
        let key = (
            source.module().into(),
            source.module_version().into(),
            source.dataset().into(),
        );
        self.page_decoders
            .get(&key)
            .map(AsRef::as_ref)
            .ok_or(SourceQueryError::Unavailable)
    }

    pub fn executor(
        &self,
        module: &str,
    ) -> Result<&Arc<dyn SourceQueryExecutor>, SourceQueryError> {
        self.executors
            .get(module)
            .ok_or(SourceQueryError::Unavailable)
    }
}
