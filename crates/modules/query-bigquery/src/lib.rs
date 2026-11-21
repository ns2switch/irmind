#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod compiler;
mod protocol;
#[cfg(test)]
mod tests;

use irmind_app::{
    AppError, CancellationToken, Tool, async_trait,
    source_queries::{
        AdmittedSourceQuery, CancelObservationV1, CompiledSourceQueryV1, ExecutionObservationV1,
        QueryAccounting, QueryEstimate, QueryExecutionRef, QueryExecutionStatus, QueryPreflightV1,
        QueryResponsePage, QueryResultCursor, QueryTime, ResolvedQuerySourceV1, SourceQueryError,
        SourceQueryExecutor, SourceQueryLeasePhase, SourceQueryLimits, SourceQueryModuleV1,
        SourceQueryUsage, SourceQueryV1, SubmitObservationV1, canonical_query_json,
    },
};
use irmind_domain::AuthorizedCall;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use std::time::Duration;

pub struct BigQuery {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    source: ResolvedQuerySourceV1,
    limits: SourceQueryLimits,
    token: SecretString,
}

impl BigQuery {
    pub fn new(
        source: ResolvedQuerySourceV1,
        limits: SourceQueryLimits,
        access_token: SecretString,
    ) -> Result<Self, AppError> {
        limits.validate()?;
        compiler::table_layout(&source)?;
        if source.module() != compiler::MODULE
            || source.module_version() != "1"
            || limits
                .scan_bytes
                .is_none_or(|cap| cap < protocol::MINIMUM_BILLED_BYTES)
            || !compiler::identifier(source.owner(), true)
            || !compiler::identifier(source.location(), true)
            || access_token.expose_secret().is_empty()
            || access_token.expose_secret().len() > 8192
            || !access_token
                .expose_secret()
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err(SourceQueryError::Invalid.into());
        }
        Ok(Self {
            client: irmind_http::client_builder(Duration::from_secs(limits.deadline_seconds), true)
                .build()
                .map_err(|_| AppError::RemoteTool)?,
            endpoint: reqwest::Url::parse("https://bigquery.googleapis.com/bigquery/v2/")
                .map_err(|_| SourceQueryError::Invalid)?,
            source,
            limits,
            token: access_token,
        })
    }

    fn check(
        &self,
        lease: &AdmittedSourceQuery,
        phase: SourceQueryLeasePhase,
        job: Option<&QueryExecutionRef>,
    ) -> Result<(), AppError> {
        lease.check(compiler::MODULE, self.source.id(), phase, job)?;
        if lease.source() != &self.source
            || lease.limits() != &self.limits
            || lease.compiled().translator().id != "bigquery-cloud-audit"
        {
            return Err(SourceQueryError::Scope.into());
        }
        Ok(())
    }
}

#[async_trait]
impl SourceQueryExecutor for BigQuery {
    fn descriptor(&self) -> SourceQueryModuleV1 {
        compiler::descriptor()
    }

    fn compile(
        &self,
        source: &ResolvedQuerySourceV1,
        query: &SourceQueryV1,
    ) -> Result<CompiledSourceQueryV1, AppError> {
        if source != &self.source {
            return Err(SourceQueryError::Scope.into());
        }
        Ok(compiler::translate(source, query, &self.limits)?)
    }

    async fn preflight(
        &self,
        call: &AuthorizedCall,
        compiled: &CompiledSourceQueryV1,
        cancel: &CancellationToken,
    ) -> Result<QueryPreflightV1, AppError> {
        if call.tool() != &Tool::SourceQuery
            || call.arg("source") != Some(self.source.id())
            || self.compile(
                &self.source,
                &SourceQueryV1::from_proposal(call.proposal_args())?,
            )? != *compiled
        {
            return Err(SourceQueryError::Scope.into());
        }
        let estimate = self.dry_run(compiled, cancel).await?;
        Ok(QueryPreflightV1 {
            plan_digest: irmind_app::hex(&irmind_app::sha256(&canonical_query_json(compiled)?)),
            observed_at: QueryTime::parse(&irmind_calendar::Utc::now().to_rfc3339())?,
            accounting: QueryAccounting::ScanPriced,
            estimate: QueryEstimate {
                unit: "billed_bytes".into(),
                value: Some(estimate.billed_bytes),
                basis: "dry_run".into(),
                reliable: estimate.reliable,
            },
            provider_ceiling: self.limits.scan_bytes,
            source_metadata: json!({"location": self.source.location()}),
            uncertainty: if estimate.reliable {
                vec![]
            } else {
                vec!["dry_run_billed_bytes_unverified".into()]
            },
        })
    }

    async fn submit(
        &self,
        lease: &AdmittedSourceQuery,
        cancel: &CancellationToken,
    ) -> Result<SubmitObservationV1, AppError> {
        self.check(lease, SourceQueryLeasePhase::Submit, None)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let job = protocol::job_id(lease.execution_key())?;
        match self.insert(lease.compiled(), &job, cancel).await {
            Ok(true) => Ok(SubmitObservationV1::Accepted(QueryExecutionRef::new(
                lease.plan(),
                lease.attempt(),
                &job,
            )?)),
            _ => Ok(SubmitObservationV1::Unknown),
        }
    }

    async fn reconcile(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cancel: &CancellationToken,
    ) -> Result<ExecutionObservationV1, AppError> {
        self.check(lease, SourceQueryLeasePhase::Reconcile, Some(execution))?;
        let job = protocol::job_id(lease.execution_key())?;
        if execution.provider_id() != job && execution.provider_id() != lease.execution_key() {
            return Err(SourceQueryError::Scope.into());
        }
        self.observe(lease.compiled(), &job, cancel).await
    }

    async fn fetch(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cursor: &QueryResultCursor,
        cancel: &CancellationToken,
    ) -> Result<QueryResponsePage, AppError> {
        self.check(lease, SourceQueryLeasePhase::Fetch, Some(execution))?;
        cursor.check(execution)?;
        if execution.provider_id() != protocol::job_id(lease.execution_key())? {
            return Err(SourceQueryError::Scope.into());
        }
        self.page(execution.provider_id(), cursor.token(), cancel)
            .await
    }

    async fn cancel(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cancel: &CancellationToken,
    ) -> Result<CancelObservationV1, AppError> {
        self.check(lease, SourceQueryLeasePhase::Cancel, Some(execution))?;
        if execution.provider_id() != protocol::job_id(lease.execution_key())? {
            return Err(SourceQueryError::Scope.into());
        }
        self.stop(execution.provider_id(), cancel).await
    }
}
