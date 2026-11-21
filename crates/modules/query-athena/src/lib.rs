#![forbid(unsafe_code)]

mod capture;
mod compile;
pub use capture::AthenaCaptureDecoder;
mod protocol;

use aws_credential_types::Credentials;
pub use compile::translate;
use irmind_app::{
    AppError, CancellationToken, Clock, Tool, async_trait,
    source_queries::{
        AdmittedSourceQuery, CancelObservationV1, CompiledSourceQueryV1, ExecutionObservationV1,
        QueryAccounting, QueryEstimate, QueryExecutionRef, QueryPreflightV1, QueryResponsePage,
        QueryResultCursor, QueryTime, ResolvedQuerySourceV1, SourceQueryError, SourceQueryExecutor,
        SourceQueryLeasePhase, SourceQueryLimits, SourceQueryModuleV1, SourceQueryV1,
        SubmitObservationV1, canonical_query_json,
    },
};
use irmind_domain::AuthorizedCall;
use serde_json::json;
use std::{sync::Arc, time::Duration};

pub struct Athena {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    source: ResolvedQuerySourceV1,
    clock: Arc<dyn Clock>,
    limits: SourceQueryLimits,
    workgroup: String,
    credentials: Credentials,
}

impl Athena {
    #[allow(clippy::too_many_arguments)]
    pub fn with_explicit_keys(
        source: ResolvedQuerySourceV1,
        limits: SourceQueryLimits,
        workgroup: &str,
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        allow_cutoff_overrun: bool,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AppError> {
        Self::new(
            source,
            limits,
            workgroup,
            Credentials::new(
                access_key,
                secret_key,
                session_token.map(str::to_owned),
                None,
                "irmind-keyring",
            ),
            allow_cutoff_overrun,
            clock,
        )
    }

    /// The profile must opt in to Athena's cancellation threshold. Policies
    /// requiring a strictly enforced hard scan ceiling leave this profile unavailable.
    pub fn new(
        source: ResolvedQuerySourceV1,
        limits: SourceQueryLimits,
        dedicated_workgroup: &str,
        credentials: Credentials,
        allow_cutoff_overrun: bool,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AppError> {
        let region = source.location();
        if !allow_cutoff_overrun {
            return Err(SourceQueryError::Unavailable.into());
        }
        if source.module() != compile::MODULE
            || source.module_version() != "1"
            || !compile::identifier(dedicated_workgroup)
            || dedicated_workgroup == "primary"
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || region.len() > 32
            || credentials.access_key_id().is_empty()
            || credentials.secret_access_key().is_empty()
            || limits
                .scan_bytes
                .is_none_or(|cap| cap < protocol::MINIMUM_BILLED_BYTES)
        {
            return Err(SourceQueryError::Invalid.into());
        }
        limits.validate()?;
        let endpoint = reqwest::Url::parse(&format!("https://athena.{region}.amazonaws.com/"))
            .map_err(|_| SourceQueryError::Invalid)?;
        let client =
            irmind_http::client_builder(Duration::from_secs(limits.deadline_seconds), true)
                .build()
                .map_err(|_| AppError::RemoteTool)?;
        Ok(Self {
            client,
            endpoint,
            source,
            clock,
            limits,
            workgroup: dedicated_workgroup.into(),
            credentials,
        })
    }

    fn check(
        &self,
        lease: &AdmittedSourceQuery,
        phase: SourceQueryLeasePhase,
        execution: Option<&QueryExecutionRef>,
    ) -> Result<(), AppError> {
        lease.check(compile::MODULE, self.source.id(), phase, execution)?;
        if lease.source() != &self.source
            || lease.limits() != &self.limits
            || lease.compiled().translator().id != "athena-cloudtrail"
        {
            return Err(SourceQueryError::Scope.into());
        }
        Ok(())
    }

    async fn scan_cutoff(&self, cancel: &CancellationToken) -> Result<u64, AppError> {
        let body = self
            .post(
                "GetWorkGroup",
                &json!({"WorkGroup":self.workgroup}),
                protocol::METADATA_LIMIT,
                cancel,
            )
            .await?;
        let workgroup = &body["WorkGroup"];
        let configuration = &workgroup["Configuration"];
        let cutoff = configuration["BytesScannedCutoffPerQuery"]
            .as_u64()
            .filter(|bytes| *bytes >= 10_000_000)
            .and_then(protocol::billable_bytes)
            .filter(|bytes| Some(*bytes) <= self.limits.scan_bytes)
            .ok_or(SourceQueryError::Unavailable)?;
        if workgroup["Name"] != self.workgroup
            || workgroup["State"] != "ENABLED"
            || configuration["EnforceWorkGroupConfiguration"] != true
            || configuration["EngineVersion"]["EffectiveEngineVersion"] != "Athena engine version 3"
        {
            return Err(SourceQueryError::Unavailable.into());
        }
        Ok(cutoff)
    }

    fn workgroup_facts(&self, cutoff: u64) -> serde_json::Value {
        json!({"workgroup": self.workgroup, "cutoff_semantics": "cancel_after_threshold", "billed_ceiling_bytes": cutoff})
    }

    async fn check_workgroup_facts(
        &self,
        lease: &AdmittedSourceQuery,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let cutoff = self.scan_cutoff(cancel).await?;
        if &self.workgroup_facts(cutoff) != lease.source_metadata() {
            return Err(SourceQueryError::Scope.into());
        }
        Ok(())
    }
}

#[async_trait]
impl SourceQueryExecutor for Athena {
    fn descriptor(&self) -> SourceQueryModuleV1 {
        compile::descriptor()
    }

    fn compile(
        &self,
        source: &ResolvedQuerySourceV1,
        query: &SourceQueryV1,
    ) -> Result<CompiledSourceQueryV1, AppError> {
        if source != &self.source {
            return Err(SourceQueryError::Scope.into());
        }
        Ok(translate(source, query, &self.limits)?)
    }

    async fn preflight(
        &self,
        call: &AuthorizedCall,
        query: &CompiledSourceQueryV1,
        cancel: &CancellationToken,
    ) -> Result<QueryPreflightV1, AppError> {
        if call.tool() != &Tool::SourceQuery
            || call.arg("source") != Some(self.source.id())
            || &self.compile(
                &self.source,
                &SourceQueryV1::from_proposal(call.proposal_args())?,
            )? != query
        {
            return Err(SourceQueryError::Scope.into());
        }
        let cutoff = self.scan_cutoff(cancel).await?;
        Ok(QueryPreflightV1 {
            // The workflow binds this compiler commitment to the complete
            // scope and reservation context when it builds the signed plan.
            plan_digest: irmind_app::hex(&irmind_app::sha256(&canonical_query_json(query)?)),
            observed_at: QueryTime::from_clock(self.clock.as_ref())?,
            accounting: QueryAccounting::ScanPriced,
            estimate: QueryEstimate {
                unit: "billed_bytes".into(),
                value: None,
                basis: "workgroup_cutoff".into(),
                reliable: false,
            },
            provider_ceiling: Some(cutoff),
            source_metadata: self.workgroup_facts(cutoff),
            uncertainty: vec!["no_reliable_dry_run".into()],
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
        self.check_workgroup_facts(lease, cancel).await?;
        match self
            .start(lease.compiled(), lease.execution_key(), cancel)
            .await
        {
            Ok(id) => Ok(SubmitObservationV1::Accepted(QueryExecutionRef::new(
                lease.plan(),
                lease.attempt(),
                &id,
            )?)),
            Err(_) => Ok(SubmitObservationV1::Unknown),
        }
    }

    async fn reconcile(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cancel: &CancellationToken,
    ) -> Result<ExecutionObservationV1, AppError> {
        self.check(lease, SourceQueryLeasePhase::Reconcile, Some(execution))?;
        let id = if execution.provider_id() == lease.execution_key() {
            self.check_workgroup_facts(lease, cancel).await?;
            self.start(lease.compiled(), lease.execution_key(), cancel)
                .await?
        } else {
            execution.provider_id().into()
        };
        self.observe(&id, cancel).await
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
        self.fetch_page(execution.provider_id(), cursor.token(), cancel)
            .await
    }

    async fn cancel(
        &self,
        lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef,
        cancel: &CancellationToken,
    ) -> Result<CancelObservationV1, AppError> {
        self.check(lease, SourceQueryLeasePhase::Cancel, Some(execution))?;
        self.stop(execution.provider_id(), cancel).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
