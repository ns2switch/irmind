use super::{
    AppError, AuditEventKind, AuthorizedCall, CancellationToken, CaseId, Engine, Tool, hex,
    remote_tool_error, sha256,
};

impl Engine<'_> {
    pub(crate) async fn execute_authorized(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        approved: bool,
        cancel: &CancellationToken,
    ) -> Result<(String, String), AppError> {
        let started = std::time::Instant::now();
        crate::diagnostics::tool_started(call.tool());
        let result = self
            .execute_authorized_inner(id, call, approved, cancel)
            .await;
        crate::diagnostics::tool_finished(call.tool(), result.is_ok(), started.elapsed());
        result
    }

    async fn execute_authorized_inner(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        approved: bool,
        cancel: &CancellationToken,
    ) -> Result<(String, String), AppError> {
        let payload = format!("{} {:?}", call.tool().as_str(), call.proposal_args());
        let (origin, kind) = if approved {
            (
                crate::AuditOrigin::Analyst,
                irmind_domain::AuditEventKind::ToolDispatch,
            )
        } else {
            (
                crate::AuditOrigin::Policy,
                irmind_domain::AuditEventKind::Allowed,
            )
        };
        self.audit_local(id, origin, kind, &payload, None).await?;
        let local_tool = matches!(
            call.tool(),
            Tool::EvidenceSearch
                | Tool::EvidenceRead
                | Tool::GraphSummary
                | Tool::EntityLookup
                | Tool::Neighbors
                | Tool::EntityTimeline
                | Tool::GraphPath
                | Tool::TextSearch
                | Tool::RawRecords
                | Tool::CaseAddFinding
        );
        let raw = self
            .checked_tool_result(id, call, local_tool, cancel)
            .await?;
        self.persist_tool_result(id, call, raw, cancel).await
    }

    async fn checked_tool_result(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        local_tool: bool,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let raw = self.run_authorized_tool(call, local_tool, cancel).await;
        let raw = match raw {
            Ok(raw) => raw,
            Err(AppError::Cancelled) => {
                self.audit_local(
                    id,
                    crate::AuditOrigin::System,
                    irmind_domain::AuditEventKind::Cancelled,
                    call.tool().as_str(),
                    None,
                )
                .await?;
                return Err(AppError::Cancelled);
            }
            Err(error) => {
                self.audit_local(
                    id,
                    crate::AuditOrigin::System,
                    irmind_domain::AuditEventKind::ToolError,
                    call.tool().as_str(),
                    None,
                )
                .await?;
                return Err(if local_tool {
                    error
                } else {
                    remote_tool_error(error)
                });
            }
        };
        if cancel.is_cancelled() {
            self.audit_local(
                id,
                crate::AuditOrigin::System,
                irmind_domain::AuditEventKind::Cancelled,
                call.tool().as_str(),
                None,
            )
            .await?;
            return Err(AppError::Cancelled);
        }
        if raw.len() > 5_000_000 {
            self.audit_local(
                id,
                crate::AuditOrigin::System,
                irmind_domain::AuditEventKind::ToolError,
                "tool result exceeds 5 MB",
                None,
            )
            .await?;
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyToolResultExceeds5MB,
            ));
        }
        Ok(raw)
    }

    async fn persist_tool_result(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        raw: Vec<u8>,
        cancel: &CancellationToken,
    ) -> Result<(String, String), AppError> {
        let id = id.clone();
        let call_owned = call.clone();
        let cancel_owned = cancel.clone();
        let stored = self
            .blocking_local(move |local| {
                let hash = hex(&sha256(&raw));
                local.evidence_store.put_evidence(&id, &hash, &raw)?;
                local.audit(
                    &id,
                    crate::AuditOrigin::System,
                    irmind_domain::AuditEventKind::ToolResult,
                    &format!("{} bytes from {}", raw.len(), call_owned.tool().as_str()),
                    Some(&hash),
                )?;
                local.index_remote_result(&id, &call_owned, &hash, &raw, &cancel_owned)?;
                let screened = local.screen_model_result(
                    &id,
                    &raw,
                    AuditEventKind::ToolResult.as_str(),
                    Some(&hash),
                )?;
                Ok((screened, hash))
            })
            .await;
        if matches!(stored, Err(AppError::Cancelled)) {
            self.audit_local(
                call.case_id(),
                crate::AuditOrigin::System,
                irmind_domain::AuditEventKind::Cancelled,
                call.tool().as_str(),
                None,
            )
            .await?;
        }
        stored
    }

    async fn run_authorized_tool(
        &self,
        call: &AuthorizedCall,
        local_tool: bool,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if local_tool {
            if cancel.is_cancelled() {
                Err(AppError::Cancelled)
            } else {
                let call = call.clone();
                self.blocking_local(move |local| local.execute_local_tool(&call))
                    .await
            }
        } else {
            tokio::select! {
                biased;
                () = cancel.cancelled() => Err(AppError::Cancelled),
                result = async {
                    Ok(match call.tool() {
                    Tool::SiemSearch | Tool::SiemGetAlert => self.dispatch_siem(call, cancel).await?,
                    Tool::CloudAuditEvents | Tool::CloudIdentity => self.dispatch_cloud(call, cancel).await?,
                    Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections => {
                        self.dispatch_edr(call, cancel).await?
                    }
                    Tool::ThreatIntelInternal => self.dispatch_internal_intel(call, cancel).await?,
                    Tool::ThreatIntelExternal => self
                        .threat_intel
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyExternalIntelUnavailable))?
                        .execute(call, cancel).await?,
                    _ => return Err(AppError::Fixed(crate::FixedAppError::PolicyInvalidRemoteTool)),
                    })
                } => result,
            }
        }
    }
}
