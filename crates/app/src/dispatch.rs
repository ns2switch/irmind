mod local;
mod remote;

use crate::{
    AppError, AuditEventKind, AuthorizedCall, BTreeMap, CancellationToken, Case, CaseId, Decision,
    Engine, PendingApproval, ProposedCall, Provenance, Screened, SourceKind, Tainted, Tool, hex,
    remote_tool_error, sha256,
};

impl Engine<'_> {
    pub(crate) async fn execute_proposal(
        &self,
        case: &Case,
        proposal: ProposedCall,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let id = &case.id;
        let proposal_payload = format!("{} {:?}", proposal.tool.as_str(), proposal.args);
        let case_owned = case.clone();
        let decision = self
            .blocking_local(move |local| {
                let id = &case_owned.id;
                local.audit(id, "model", "Proposal", &proposal_payload, None)?;
                let completed_calls = local.completed_calls_unlocked(id)?;
                if let Err(reason) = local.policy.permits(&proposal.tool, completed_calls) {
                    return Ok(Decision::Deny(reason));
                }
                let next_seq = local
                    .audit_log
                    .last_entry(id)?
                    .map_or(1, |entry| entry.seq + 1);
                let tainted = Tainted::from_external(
                    proposal,
                    Provenance::new(
                        sha256(proposal_payload.as_bytes()),
                        None,
                        SourceKind::ModelProposal,
                    ),
                );
                Ok(irmind_domain::evaluate_tainted_with_rules(
                    &case_owned,
                    tainted,
                    next_seq,
                    local.mode,
                    local.turn_has_detections(id)?,
                    local.clock.now()?,
                    &local.policy,
                ))
            })
            .await?;
        match decision {
            Decision::Deny(reason) => {
                self.audit_local(id, "policy", "Denied", reason, None)
                    .await?;
                Ok(format!("denied: {reason}"))
            }
            Decision::NeedsApproval(pending) => {
                if let Some(reason) = self.pending_unavailable_reason(&pending) {
                    self.audit_local(id, "policy", "Denied", reason, None)
                        .await?;
                    return Ok(format!("denied: {reason}"));
                }
                let id_owned = id.clone();
                let mode = self.mode;
                let challenge_id = self
                    .blocking_local(move |local| local.audit_pending(&id_owned, &pending, mode))
                    .await?;
                Ok(format!(
                    "approval pending: {challenge_id}; request was not executed"
                ))
            }
            Decision::Allow(call) => {
                if let Some(reason) = self.unavailable_reason(&call) {
                    self.audit_local(id, "policy", "Denied", reason, None)
                        .await?;
                    return Ok(format!("denied: {reason}"));
                }
                let (screened, _) = self.execute_authorized(id, &call, false, cancel).await?;
                Ok(screened)
            }
        }
    }

    pub(crate) fn unavailable_reason(&self, call: &AuthorizedCall) -> Option<&'static str> {
        self.source_unavailable_reason(call.tool(), call.arg("source"))
            .or_else(|| {
                (call.tool() == &Tool::ThreatIntelExternal && self.threat_intel.is_none())
                    .then_some("external intelligence module unavailable")
            })
    }

    fn pending_unavailable_reason(&self, pending: &PendingApproval) -> Option<&'static str> {
        self.source_unavailable_reason(
            &pending.proposal().tool,
            pending.proposal().args.get("source").map(String::as_str),
        )
    }

    fn source_unavailable_reason(&self, tool: &Tool, source: Option<&str>) -> Option<&'static str> {
        match tool {
            Tool::SiemSearch if !self.siem_available(source) => Some("SIEM source unavailable"),
            Tool::CloudAuditEvents | Tool::CloudIdentity if !self.cloud_available(source) => {
                Some("cloud audit source unavailable")
            }
            Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections
                if !self.edr_available(source, tool) =>
            {
                Some("EDR source unavailable")
            }
            Tool::ThreatIntelInternal if !self.internal_intel_available(source) => {
                Some("internal intelligence source unavailable")
            }
            _ => None,
        }
    }

    pub(crate) fn turn_has_detections(&self, id: &CaseId) -> Result<bool, AppError> {
        for entry in self.audit_log.entries(id)?.iter().rev() {
            if entry.kind == irmind_domain::AuditEventKind::InjectionDetected {
                return Ok(true);
            }
            if entry.kind == irmind_domain::AuditEventKind::Prompt {
                break;
            }
        }
        Ok(false)
    }

    pub(crate) async fn execute_authorized(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        approved: bool,
        cancel: &CancellationToken,
    ) -> Result<(String, String), AppError> {
        let payload = format!("{} {:?}", call.tool().as_str(), call.proposal_args());
        let (origin, kind) = if approved {
            ("analyst", "ToolDispatch")
        } else {
            ("policy", "Allowed")
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
        let raw = self.run_authorized_tool(call, local_tool, cancel).await;
        let raw = match raw {
            Ok(raw) => raw,
            Err(AppError::Cancelled) => {
                self.audit_local(id, "system", "Cancelled", call.tool().as_str(), None)
                    .await?;
                return Err(AppError::Cancelled);
            }
            Err(error) => {
                self.audit_local(id, "system", "ToolError", call.tool().as_str(), None)
                    .await?;
                return Err(if local_tool {
                    error
                } else {
                    remote_tool_error(error)
                });
            }
        };
        if cancel.is_cancelled() {
            self.audit_local(id, "system", "Cancelled", call.tool().as_str(), None)
                .await?;
            return Err(AppError::Cancelled);
        }
        if raw.len() > 5_000_000 {
            self.audit_local(id, "system", "ToolError", "tool result exceeds 5 MB", None)
                .await?;
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyToolResultExceeds5MB,
            ));
        }
        self.persist_tool_result(id, call, raw, cancel).await
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
                    "system",
                    "ToolResult",
                    &format!("{} bytes from {}", raw.len(), call_owned.tool().as_str()),
                    Some(&hash),
                )?;
                local.index_remote_result(&id, &call_owned, &hash, &raw, &cancel_owned)?;
                let screened = local.screen_model_result(&id, &raw, "ToolResult", Some(&hash))?;
                Ok((screened, hash))
            })
            .await;
        if matches!(stored, Err(AppError::Cancelled)) {
            self.audit_local(
                call.case_id(),
                "system",
                "Cancelled",
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
                    Tool::SiemSearch => self.dispatch_siem(call, cancel).await?,
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

    pub(crate) fn screen_and_audit(
        &self,
        id: &CaseId,
        text: &str,
        source: &str,
        evidence: Option<&str>,
    ) -> Result<Screened, AppError> {
        let screened = self.guard.screen(text)?;
        let mut counts = BTreeMap::<&str, usize>::new();
        for rule in &screened.detections {
            *counts.entry(rule).or_default() += 1;
        }
        for (rule, count) in counts {
            self.audit(
                id,
                "guard",
                "InjectionDetected",
                &format!("source={source};rule={rule};count={count}"),
                evidence,
            )?;
        }
        Ok(screened)
    }

    pub(crate) fn screen_model_result(
        &self,
        id: &CaseId,
        raw: &[u8],
        source: &str,
        evidence: Option<&str>,
    ) -> Result<String, AppError> {
        let _tainted = Tainted::from_external(
            raw,
            Provenance::new(sha256(raw), None, SourceKind::ToolResult),
        );
        let Ok(text) = std::str::from_utf8(raw) else {
            self.audit(id, "guard", "BinaryResultOmitted", source, evidence)?;
            let message = "[BINARY RESULT OMITTED]";
            return Ok(message[..message.len().min(self.policy.max_model_result_bytes)].into());
        };
        let mut preview_end = text.len().min(1_000_000);
        while !text.is_char_boundary(preview_end) {
            preview_end -= 1;
        }
        let mut visible = self
            .screen_and_audit(id, &text[..preview_end], source, evidence)?
            .text;
        let limit = self.policy.max_model_result_bytes;
        if preview_end < text.len() || visible.len() > limit {
            let hint = "[TRUNCATED]";
            if limit <= hint.len() {
                return Ok(hint[..limit].into());
            }
            let mut end = (limit - hint.len()).min(visible.len());
            while !visible.is_char_boundary(end) {
                end -= 1;
            }
            visible.truncate(end);
            visible.push_str(hint);
        }
        Ok(visible)
    }

    pub(crate) fn completed_calls_unlocked(&self, id: &CaseId) -> Result<usize, AppError> {
        Ok(self
            .audit_log
            .entries(id)?
            .iter()
            .filter(|entry| {
                matches!(
                    entry.kind,
                    AuditEventKind::Allowed | AuditEventKind::ToolDispatch
                )
            })
            .count())
    }
}
