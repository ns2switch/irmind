#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod capture;
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
use std::{collections::BTreeMap, sync::Mutex, time::Duration};

struct ReadyResponse {
    reference: QueryExecutionRef,
    response: reqwest::Response,
}

pub use capture::AzureAnalyticsCaptureDecoder;

pub struct AzureLogAnalytics {
    client: reqwest::Client,
    identity: reqwest::Url,
    arm: reqwest::Url,
    logs: reqwest::Url,
    source: ResolvedQuerySourceV1,
    limits: SourceQueryLimits,
    table_path: String,
    client_id: String,
    client_secret: SecretString,
    ready: Mutex<BTreeMap<String, ReadyResponse>>,
}

impl AzureLogAnalytics {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: ResolvedQuerySourceV1,
        limits: SourceQueryLimits,
        tenant: &str,
        client_id: &str,
        client_secret: SecretString,
        subscription: &str,
        resource_group: &str,
        workspace_name: &str,
    ) -> Result<Self, AppError> {
        limits.validate()?;
        if source.module() != compiler::MODULE
            || source.module_version() != "1"
            || limits.scan_bytes.is_some()
            || [tenant, client_id, subscription, source.owner()]
                .iter()
                .any(|s| uuid::Uuid::parse_str(s).is_err())
            || [resource_group, workspace_name].iter().any(|s| {
                s.is_empty()
                    || s.len() > 90
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            })
            || !compiler::TABLES
                .iter()
                .any(|(dataset, table)| *dataset == source.dataset() && *table == source.table())
            || client_secret.expose_secret().is_empty()
            || client_secret.expose_secret().len() > 8192
        {
            return Err(SourceQueryError::Invalid.into());
        }
        let table_path = format!(
            "subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/tables/{}",
            source.table()
        );
        let parse = |url: &str| reqwest::Url::parse(url).map_err(|_| SourceQueryError::Invalid);
        Ok(Self {
            client: irmind_http::client_builder(Duration::from_secs(limits.deadline_seconds), true)
                .build()
                .map_err(|_| AppError::RemoteTool)?,
            identity: parse(&format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            ))?,
            arm: parse("https://management.azure.com/")?,
            logs: parse("https://api.loganalytics.azure.com/v1/")?,
            source,
            limits,
            table_path,
            client_id: client_id.into(),
            client_secret,
            ready: Mutex::new(BTreeMap::new()),
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
            || lease.compiled().translator().id != "azure-analytics"
        {
            return Err(SourceQueryError::Scope.into());
        }
        Ok(())
    }
}

#[async_trait]
impl SourceQueryExecutor for AzureLogAnalytics {
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
        let metadata = self.analytics_plan(cancel).await?;
        Ok(QueryPreflightV1 {
            plan_digest: irmind_app::hex(&irmind_app::sha256(&canonical_query_json(compiled)?)),
            observed_at: QueryTime::parse(
                &irmind_calendar::Utc::now()
                    .to_rfc3339_opts(irmind_calendar::SecondsFormat::Secs, true),
            )?,
            accounting: QueryAccounting::AnalyticsNoQueryCharge,
            estimate: QueryEstimate {
                unit: "scanned_bytes".into(),
                value: None,
                basis: "not_reported".into(),
                reliable: false,
            },
            provider_ceiling: None,
            source_metadata: metadata,
            uncertainty: vec!["not_reported".into()],
        })
    }

    async fn submit(
        &self,
        lease: &AdmittedSourceQuery,
        cancel: &CancellationToken,
    ) -> Result<SubmitObservationV1, AppError> {
        self.check(lease, SourceQueryLeasePhase::Submit, None)?;
        let previous = self.analytics_plan(cancel).await?;
        if &previous != lease.source_metadata() {
            return Err(SourceQueryError::Scope.into());
        }
        let Ok(response) = self.query(lease.compiled(), cancel).await else {
            return Ok(SubmitObservationV1::Unknown);
        };
        let Some(id) = response
            .headers()
            .get("x-ms-request-id")
            .and_then(|id| id.to_str().ok())
        else {
            return Ok(SubmitObservationV1::Unknown);
        };
        let reference = QueryExecutionRef::new(lease.plan(), lease.attempt(), id)?;
        if self.analytics_plan(cancel).await.ok().as_ref() != Some(&previous) {
            return Ok(SubmitObservationV1::Unknown);
        }
        let mut ready = self.ready.lock().map_err(|_| AppError::RemoteTool)?;
        if ready.len() as u64 >= self.limits.concurrency || ready.contains_key(lease.plan()) {
            return Ok(SubmitObservationV1::Unknown);
        }
        ready.insert(
            lease.plan().into(),
            ReadyResponse {
                reference: reference.clone(),
                response,
            },
        );
        Ok(SubmitObservationV1::Accepted(reference))
    }

    async fn reconcile(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cancel: &CancellationToken,
    ) -> Result<ExecutionObservationV1, AppError> {
        self.check(lease, SourceQueryLeasePhase::Reconcile, Some(execution))?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let ready = self.ready.lock().map_err(|_| AppError::RemoteTool)?;
        let available = ready
            .get(lease.plan())
            .is_some_and(|response| response.reference == *execution);
        Ok(ExecutionObservationV1 {
            status: if available {
                QueryExecutionStatus::Partial
            } else {
                QueryExecutionStatus::Unknown
            },
            request_id: available.then(|| execution.provider_id().to_owned()),
            usage: SourceQueryUsage {
                scanned_bytes: None,
                processed_bytes: None,
                billed_bytes: None,
                returned_wire_bytes: 0,
                returned_decoded_bytes: 0,
                query_price_basis: QueryAccounting::AnalyticsNoQueryCharge,
            },
            source_observation: Some(
                json!({"response_available":available,"remote_job_lookup":false}),
            ),
        })
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
        if cursor.ordinal() != 0 || cursor.token().is_some() {
            return Err(SourceQueryError::Invalid.into());
        }
        let mut ready = self.ready.lock().map_err(|_| AppError::RemoteTool)?;
        if ready
            .get(lease.plan())
            .is_none_or(|response| response.reference != *execution)
        {
            return Err(SourceQueryError::Unresolved.into());
        }
        let response = ready
            .remove(lease.plan())
            .ok_or(SourceQueryError::Unresolved)?
            .response;
        Ok(self.single_page(response, execution.provider_id().into(), cancel))
    }

    async fn cancel(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cancel: &CancellationToken,
    ) -> Result<CancelObservationV1, AppError> {
        self.check(lease, SourceQueryLeasePhase::Cancel, Some(execution))?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut ready = self.ready.lock().map_err(|_| AppError::RemoteTool)?;
        if ready
            .get(lease.plan())
            .is_some_and(|response| response.reference == *execution)
        {
            ready.remove(lease.plan());
        }
        Ok(CancelObservationV1::Unsupported)
    }
}
