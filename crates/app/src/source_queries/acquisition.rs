use super::{
    AdmittedSourceQuery, ExecutionObservationV1, QueryExecutionRef, QueryExecutionStatus,
    QueryResultCursor, QueryTime, SignedSourceQueryAdmission, SourceQueryError,
    SourceQueryExecutionV1, SourceQueryExecutor, SourceQueryLeasePhase, SourceQueryPlanV1,
    SourceQueryReservationV1, SourceQueryResultV1, SourceQuerySettlementV1, SourceQueryUsage,
    SubmitObservationV1, canonical_query_json, verify_query_capture,
};
use crate::{
    AppError, AuditEventKind, AuditOrigin, AuthorizedCall, CancellationToken, CaseId, Engine,
    SignedEntry,
};
use futures_util::StreamExt as _;
use irmind_domain::{EvidenceHash, IndexedTime};
use std::{
    io::{Seek as _, Write as _},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Debug)]
pub struct AcquiredSourceQuery {
    pub capture: EvidenceHash,
    pub rows: u64,
    pub rejected_rows: u64,
    pub completeness: Vec<String>,
}

impl AcquiredSourceQuery {
    pub fn display_summary(&self) -> String {
        let coverage = if self.completeness.is_empty() {
            "complete".to_owned()
        } else {
            self.completeness.join(", ")
        };
        format!(
            "Source query capture {}. Rows indexed {}, rows rejected {}. Coverage {}.",
            self.capture.as_str(),
            self.rows,
            self.rejected_rows,
            coverage,
        )
    }
}

struct StagedQuery {
    file: tempfile::NamedTempFile,
    summary: super::QueryCaptureSummary,
    rejected: u64,
    completeness: Vec<String>,
    wire_bytes: u64,
}

impl Engine<'_> {
    /// Execute a signed admission and atomically publish the validated capture
    /// and all derived artifacts. No provider sees an uncommitted lease.
    pub fn acquire_signed_source_query(
        &self,
        authorized: &AuthorizedCall,
        admission: SignedSourceQueryAdmission<'_>,
        cancel: &CancellationToken,
    ) -> Result<AcquiredSourceQuery, AppError> {
        crate::run_async(self.acquire_signed_source_query_cancelable(authorized, admission, cancel))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep the lease transitions and terminal receipt in one lifecycle"
    )]
    pub async fn acquire_signed_source_query_cancelable(
        &self,
        authorized: &AuthorizedCall,
        admission: SignedSourceQueryAdmission<'_>,
        cancel: &CancellationToken,
    ) -> Result<AcquiredSourceQuery, AppError> {
        let plan = SourceQueryPlanV1::decode(admission.plan.payload.as_bytes())?;
        plan.check_authorized_call(authorized)?;
        let ports = self
            .source_queries
            .as_ref()
            .ok_or(SourceQueryError::Unavailable)?;
        let decoder = ports.page_decoder(plan.source())?;
        let identity = decoder.identity();
        if plan.decoder.id != identity.name || plan.decoder.version != identity.version {
            return Err(SourceQueryError::Unavailable.into());
        }
        let executor = ports.executor_for(plan.source())?;
        let deadline = Instant::now() + Duration::from_secs(plan.limits().deadline_seconds);
        let reservation =
            SourceQueryReservationV1::decode(admission.reservation.payload.as_bytes())?;
        let reservation = reservation.content_id()?;
        let SubmitObservationV1::Accepted(job) = self
            .submit_signed_source_query_cancelable(authorized, admission, cancel)
            .await?
        else {
            return Err(SourceQueryError::Unresolved.into());
        };
        let intent = SourceQueryExecutionV1::decode(admission.intent.payload.as_bytes())?;
        let case = authorized.case_id();
        let mut lease = AdmittedSourceQuery {
            case_id: case.clone(),
            plan: job.plan().into(),
            attempt: job.attempt(),
            reservation,
            source: plan.source().clone(),
            compiled: plan.compiled().clone(),
            limits: plan.limits().clone(),
            source_metadata: plan.preflight.source_metadata.clone(),
            execution_key: intent.execution_key().into(),
            phase: SourceQueryLeasePhase::Reconcile,
            execution: Some(job.clone()),
        };
        let mut observed = observe(executor.as_ref(), &lease, &job, deadline, cancel).await;
        let staged = if matches!(
            observed.status,
            QueryExecutionStatus::Succeeded | QueryExecutionStatus::Partial
        ) {
            lease.phase = SourceQueryLeasePhase::Fetch;
            self.stage_query_pages(
                executor.as_ref(),
                decoder,
                &lease,
                &job,
                plan.requested_rows(),
                deadline,
                cancel,
            )
            .await
        } else {
            Err(if cancel.is_cancelled() {
                AppError::Cancelled
            } else {
                SourceQueryError::Unresolved.into()
            })
        };
        if matches!(
            observed.status,
            QueryExecutionStatus::Unknown | QueryExecutionStatus::Running
        ) && executor.descriptor().cancellation
            || staged.is_err()
                && plan.accounting() == super::QueryAccounting::AnalyticsNoQueryCharge
        {
            lease.phase = SourceQueryLeasePhase::Cancel;
            // Bound the advisory cancellation independently of the expired deadline.
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                executor.cancel(&lease, &job, &CancellationToken::new()),
            )
            .await;
        }
        if let Ok(staged) = &staged {
            observed.usage.returned_wire_bytes = staged.wire_bytes;
            observed.usage.returned_decoded_bytes = staged.wire_bytes;
            // Analytics uses a provisional Partial observation until the stream
            // has established whether HTTP 200 carried an error alongside rows.
            if plan.accounting() == super::QueryAccounting::AnalyticsNoQueryCharge
                && staged.completeness.is_empty()
            {
                observed.status = QueryExecutionStatus::Succeeded;
            }
        }
        let terminal = self.record_query_terminal(case, &lease.reservation, &job, observed)?;
        let staged = match staged {
            Ok(staged) => staged,
            Err(error) => {
                if let Ok(settlement) = SourceQuerySettlementV1::for_terminal(&terminal, None) {
                    self.settle_query_without_capture(case, &settlement)?;
                }
                return Err(error);
            }
        };
        self.publish_staged_query(case, &plan, identity, &terminal, staged, cancel)
    }

    fn publish_staged_query(
        &self,
        case: &CaseId,
        plan: &SourceQueryPlanV1,
        identity: crate::ParserIdentity<'_>,
        terminal: &SourceQueryExecutionV1,
        staged: StagedQuery,
        cancel: &CancellationToken,
    ) -> Result<AcquiredSourceQuery, AppError> {
        let mut completeness = staged.completeness;
        if terminal.is_provider_partial()
            && !completeness
                .iter()
                .any(|reason| reason == "provider_partial")
        {
            completeness.push("provider_partial".into());
            completeness.sort();
        }
        let result = SourceQueryResultV1::for_capture(
            terminal,
            plan,
            &staged.summary,
            staged.rejected,
            completeness.clone(),
        )?;
        let settlement = SourceQuerySettlementV1::for_terminal(terminal, Some(&result))?;
        let selection = QueryCaptureSelection(identity);
        let published = self.publish_source_query_capture(
            case,
            &query_payload(&result)?,
            &query_payload(&settlement)?,
            &staged.file,
            &selection,
            cancel,
        );
        let capture = match published {
            Ok(hash) => hash,
            Err(error) => {
                let settlement = SourceQuerySettlementV1::for_terminal(terminal, None)?;
                self.settle_query_without_capture(case, &settlement)?;
                return Err(error);
            }
        };
        Ok(AcquiredSourceQuery {
            capture,
            rows: staged.summary.rows - staged.rejected,
            rejected_rows: staged.rejected,
            completeness,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn stage_query_pages(
        &self,
        executor: &dyn SourceQueryExecutor,
        decoder: &dyn super::SourceQueryPageDecoder,
        lease: &AdmittedSourceQuery,
        job: &QueryExecutionRef,
        requested_rows: u64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<StagedQuery, AppError> {
        let (mut writer, output) =
            self.prepare_source_query_capture_spools(lease.case_id(), lease.reservation(), cancel)?;
        let store = self
            .large_case_store
            .as_deref()
            .ok_or(SourceQueryError::Unavailable)?;
        let mut page = store.create_object_spool(lease.case_id(), lease.limits.retained_bytes)?;
        let mut cursor = QueryResultCursor::first(job);
        let mut wire_bytes = 0_u64;
        let mut partial = false;
        let mut local_limit = false;
        loop {
            let transferred = download_page(
                executor,
                lease,
                job,
                &cursor,
                &mut page,
                writer.remaining_capture_bytes(),
                deadline,
                cancel,
            )
            .await;
            let (bytes, token) = match transferred {
                Ok(value) => value,
                Err(AppError::Cancelled) => return Err(AppError::Cancelled),
                Err(AppError::Policy(reason))
                    if reason == SourceQueryError::Limit.to_string() && cursor.ordinal() > 0 =>
                {
                    local_limit = true;
                    break;
                }
                Err(_) if cursor.ordinal() > 0 => {
                    partial = true;
                    break;
                }
                Err(error) => return Err(error),
            };
            wire_bytes = wire_bytes
                .checked_add(bytes)
                .ok_or(SourceQueryError::Limit)?;
            let token = match writer.stage_inspected_page(
                page.as_file_mut(),
                decoder,
                token.as_deref(),
                requested_rows,
                cancel,
            ) {
                Ok(token) => token,
                Err(AppError::Policy(reason))
                    if reason == SourceQueryError::Limit.to_string() && cursor.ordinal() > 0 =>
                {
                    local_limit = true;
                    break;
                }
                Err(error) => return Err(error),
            };
            if writer.inspected_counts().0 >= requested_rows {
                local_limit = true;
                break;
            }
            let Some(token) = token else {
                break;
            };
            let Ok(next) = cursor.next(job, &token) else {
                partial = true;
                break;
            };
            cursor = next;
        }
        finish_capture(writer, output, wire_bytes, local_limit, partial, cancel)
    }

    fn query_signer(&self) -> Result<Engine<'static>, AppError> {
        let mut handle = self.local_handle();
        handle.signer = self
            .skills
            .as_ref()
            .ok_or(SourceQueryError::Unavailable)?
            .agent
            .clone();
        Ok(handle)
    }

    fn record_query_terminal(
        &self,
        case: &CaseId,
        reservation: &str,
        job: &QueryExecutionRef,
        observed: ExecutionObservationV1,
    ) -> Result<SourceQueryExecutionV1, AppError> {
        let cancel = CancellationToken::new();
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, &cancel)?;
        let entries = self.audit_log.entries(case)?;
        let accepted = entries
            .iter()
            .rev()
            .filter(|entry| entry.kind == AuditEventKind::SourceQueryExecutionV1)
            .map(|entry| SourceQueryExecutionV1::decode(entry.payload.as_bytes()))
            .find_map(|entry| {
                entry
                    .map(|entry| (entry.reservation() == reservation).then_some(entry))
                    .transpose()
            })
            .ok_or(SourceQueryError::Unresolved)??;
        if !accepted.accepts_execution(reservation, job) {
            return Err(SourceQueryError::Unresolved.into());
        }
        let at = IndexedTime::from_epoch_decimal(&self.clock.now()?.to_string(), false)
            .map_err(|_| SourceQueryError::Invalid)?;
        let record = accepted.observed_execution(observed, QueryTime::parse(&at.to_rfc3339())?)?;
        let signed = self.sign_query_frame(
            case,
            entries.last(),
            AuditEventKind::SourceQueryExecutionV1,
            &record,
        )?;
        self.persist_source_query_observation_unlocked(case, &signed, &cancel)?;
        Ok(record)
    }

    pub(super) fn sign_query_frame(
        &self,
        case: &CaseId,
        previous: Option<&SignedEntry>,
        kind: AuditEventKind,
        record: &impl serde::Serialize,
    ) -> Result<SignedEntry, AppError> {
        self.query_signer()?.signed_entry_after(
            case,
            previous,
            AuditOrigin::Agent,
            kind,
            &query_payload(record)?,
            None,
        )
    }

    fn settle_query_without_capture(
        &self,
        case: &CaseId,
        settlement: &SourceQuerySettlementV1,
    ) -> Result<(), AppError> {
        let cancel = CancellationToken::new();
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, &cancel)?;
        let mut entries = self.audit_log.entries(case)?;
        let operations = self.audit_log.global_operations()?;
        let entry = self.sign_query_frame(
            case,
            entries.last(),
            AuditEventKind::SourceQuerySettlementV1,
            settlement,
        )?;
        entries.push(entry.clone());
        super::SourceQueryJournal::replay(&entries, &operations, self.verifier.as_ref(), &cancel)?;
        self.audit_log.append(&entry)
    }
}

fn finish_capture(
    writer: super::QueryCaptureWriter<tempfile::NamedTempFile>,
    mut output: tempfile::NamedTempFile,
    wire_bytes: u64,
    local_limit: bool,
    partial: bool,
    cancel: &CancellationToken,
) -> Result<StagedQuery, AppError> {
    let (_, rejected, page_partial) = writer.inspected_counts();
    let mut completeness = Vec::new();
    if local_limit {
        completeness.push("local_limit".into());
    }
    if page_partial || partial {
        completeness.push("provider_partial".into());
    }
    if rejected > 0 {
        completeness.push("rejected".into());
    }
    writer.finish(output.as_file_mut(), cancel)?;
    output.rewind().map_err(query_spool_error)?;
    let summary = verify_query_capture(output.as_file_mut(), cancel)?;
    Ok(StagedQuery {
        file: output,
        summary,
        rejected,
        completeness,
        wire_bytes,
    })
}

async fn observe(
    executor: &dyn SourceQueryExecutor,
    lease: &AdmittedSourceQuery,
    job: &QueryExecutionRef,
    deadline: Instant,
    cancel: &CancellationToken,
) -> ExecutionObservationV1 {
    let observations = async {
        for _ in 0..64 {
            let observation = executor.reconcile(lease, job, cancel).await?;
            if !matches!(observation.status, QueryExecutionStatus::Running) {
                return Ok::<_, AppError>(observation);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(SourceQueryError::Unresolved.into())
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => {}
        observed = tokio::time::timeout_at(deadline, observations) => {
            if let Ok(Ok(observed)) = observed { return observed; }
        }
    }
    ExecutionObservationV1 {
        status: QueryExecutionStatus::Unknown,
        request_id: None,
        usage: SourceQueryUsage {
            scanned_bytes: None,
            processed_bytes: None,
            billed_bytes: None,
            returned_wire_bytes: 0,
            returned_decoded_bytes: 0,
            query_price_basis: executor.descriptor().accounting,
        },
        source_observation: None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn download_page(
    executor: &dyn SourceQueryExecutor,
    lease: &AdmittedSourceQuery,
    job: &QueryExecutionRef,
    cursor: &QueryResultCursor,
    page: &mut tempfile::NamedTempFile,
    max_bytes: u64,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(u64, Option<String>), AppError> {
    page.as_file().set_len(0).map_err(query_spool_error)?;
    page.rewind().map_err(query_spool_error)?;
    let stream = async {
        let mut incoming = executor.fetch(lease, job, cursor, cancel).await?;
        if incoming.content_encoding != "identity" {
            return Err(SourceQueryError::Invalid.into());
        }
        let mut bytes = 0_u64;
        while let Some(chunk) = incoming.chunks.next().await {
            let chunk = chunk?;
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or(SourceQueryError::Limit)?;
            if bytes > max_bytes {
                return Err(SourceQueryError::Limit.into());
            }
            page.write_all(&chunk).map_err(query_spool_error)?;
        }
        page.rewind().map_err(query_spool_error)?;
        Ok((bytes, incoming.next_token))
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(AppError::Cancelled),
        done = tokio::time::timeout_at(deadline, stream) => done.map_err(|_| SourceQueryError::Unresolved)?,
    }
}

pub(super) fn query_payload(record: &impl serde::Serialize) -> Result<String, AppError> {
    String::from_utf8(canonical_query_json(record)?).map_err(|_| SourceQueryError::Invalid.into())
}

struct QueryCaptureSelection<'a>(crate::ParserIdentity<'a>);
impl crate::StreamingEventParser for QueryCaptureSelection<'_> {
    fn parser_name(&self) -> &'static str {
        "source-query-capture"
    }
    fn streaming_version(&self) -> &'static str {
        "1"
    }
    fn identity(&self) -> crate::ParserIdentity<'_> {
        crate::ParserIdentity {
            name: self.0.name,
            version: self.0.version,
        }
    }
}

fn query_spool_error(_: std::io::Error) -> AppError {
    AppError::Storage("could not read or write the private source-query spool".into())
}
