use crate::{
    AppError, AuthorizedCall, BTreeMap, CancellationToken, Case, CaseId, Decision, Engine,
    FindingKind, ProposedCall, Provenance, Screened, SourceKind, Tainted, Tool, evaluate_tainted,
    hex, remote_tool_error, sha256,
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
                Ok(evaluate_tainted(
                    &case_owned,
                    tainted,
                    next_seq,
                    local.mode,
                    local.turn_has_detections(id)?,
                    local.clock.now()?,
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
                if pending.proposal().tool == Tool::SiemSearch
                    && !self
                        .siem_available(pending.proposal().args.get("source").map(String::as_str))
                {
                    self.audit_local(id, "policy", "Denied", "SIEM source unavailable", None)
                        .await?;
                    return Ok("denied: SIEM source unavailable".into());
                }
                if matches!(
                    pending.proposal().tool,
                    Tool::CloudAuditEvents | Tool::CloudIdentity
                ) && !self
                    .cloud_available(pending.proposal().args.get("source").map(String::as_str))
                {
                    self.audit_local(
                        id,
                        "policy",
                        "Denied",
                        "cloud audit source unavailable",
                        None,
                    )
                    .await?;
                    return Ok("denied: cloud audit source unavailable".into());
                }
                if matches!(
                    pending.proposal().tool,
                    Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections
                ) && !self.edr_available(
                    pending.proposal().args.get("source").map(String::as_str),
                    &pending.proposal().tool,
                ) {
                    self.audit_local(id, "policy", "Denied", "EDR source unavailable", None)
                        .await?;
                    return Ok("denied: EDR source unavailable".into());
                }
                if pending.proposal().tool == Tool::ThreatIntelInternal
                    && !self.internal_intel_available(
                        pending.proposal().args.get("source").map(String::as_str),
                    )
                {
                    self.audit_local(
                        id,
                        "policy",
                        "Denied",
                        "internal intelligence source unavailable",
                        None,
                    )
                    .await?;
                    return Ok("denied: internal intelligence source unavailable".into());
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
        match call.tool() {
            Tool::SiemSearch if !self.siem_available(call.arg("source")) => {
                Some("SIEM source unavailable")
            }
            Tool::CloudAuditEvents | Tool::CloudIdentity
                if !self.cloud_available(call.arg("source")) =>
            {
                Some("cloud audit source unavailable")
            }
            Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections
                if !self.edr_available(call.arg("source"), call.tool()) =>
            {
                Some("EDR source unavailable")
            }
            Tool::ThreatIntelInternal if !self.internal_intel_available(call.arg("source")) => {
                Some("internal intelligence source unavailable")
            }
            Tool::ThreatIntelExternal if self.threat_intel.is_none() => {
                Some("external intelligence module unavailable")
            }
            _ => None,
        }
    }

    pub(crate) fn turn_has_detections(&self, id: &CaseId) -> Result<bool, AppError> {
        for entry in self.audit_log.entries(id)?.iter().rev() {
            if entry.kind == "InjectionDetected" {
                return Ok(true);
            }
            if entry.kind == "Prompt" {
                break;
            }
        }
        Ok(false)
    }

    pub(crate) fn execute_local_tool(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        Ok(match call.tool() {
            Tool::EvidenceSearch => {
                let query = call
                    .arg("query")
                    .ok_or_else(|| AppError::Policy("missing query".into()))?;
                let limit = call.arg("limit").and_then(|v| v.parse().ok()).unwrap_or(10);
                self.evidence_store
                    .search_evidence(call.case_id(), query, limit)?
                    .join("\n")
                    .into_bytes()
            }
            Tool::EvidenceRead => {
                let hash = call
                    .arg("hash")
                    .ok_or_else(|| AppError::Policy("missing hash".into()))?;
                let bytes = self.evidence_store.get_evidence(call.case_id(), hash)?;
                let limit = call
                    .arg("limit")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(10);
                let max = limit * 500;
                bytes.into_iter().take(max).collect()
            }
            Tool::GraphSummary => self.graph.graph_summary(call.case_id())?.into_bytes(),
            Tool::EntityLookup => self
                .graph
                .entity_lookup(
                    call.case_id(),
                    call.arg("kind")
                        .ok_or_else(|| AppError::Policy("missing kind".into()))?,
                    call.arg("value")
                        .ok_or_else(|| AppError::Policy("missing value".into()))?,
                )?
                .into_bytes(),
            Tool::Neighbors => self
                .graph
                .neighbors(
                    call.case_id(),
                    call.arg("kind")
                        .ok_or_else(|| AppError::Policy("missing kind".into()))?,
                    call.arg("value")
                        .ok_or_else(|| AppError::Policy("missing value".into()))?,
                    call.arg("limit")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(10),
                )?
                .into_bytes(),
            Tool::EntityTimeline => self
                .graph
                .entity_timeline(
                    call.case_id(),
                    call.arg("kind")
                        .ok_or_else(|| AppError::Policy("missing kind".into()))?,
                    call.arg("value")
                        .ok_or_else(|| AppError::Policy("missing value".into()))?,
                    call.arg("limit")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(10),
                )?
                .into_bytes(),
            Tool::GraphPath => self
                .graph
                .graph_path(
                    call.case_id(),
                    (
                        call.arg("from_kind")
                            .ok_or_else(|| AppError::Policy("missing from_kind".into()))?,
                        call.arg("from_value")
                            .ok_or_else(|| AppError::Policy("missing from_value".into()))?,
                    ),
                    (
                        call.arg("to_kind")
                            .ok_or_else(|| AppError::Policy("missing to_kind".into()))?,
                        call.arg("to_value")
                            .ok_or_else(|| AppError::Policy("missing to_value".into()))?,
                    ),
                )?
                .into_bytes(),
            Tool::TextSearch => self
                .graph
                .text_search(
                    call.case_id(),
                    call.arg("query")
                        .ok_or_else(|| AppError::Policy("missing query".into()))?,
                    call.arg("limit")
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(10),
                )?
                .into_bytes(),
            Tool::RawRecords => self
                .graph
                .raw_record(
                    call.case_id(),
                    call.arg("hash")
                        .ok_or_else(|| AppError::Policy("missing hash".into()))?,
                    call.arg("index")
                        .and_then(|value| value.parse().ok())
                        .ok_or_else(|| AppError::Policy("missing index".into()))?,
                )?
                .into_bytes(),
            Tool::CaseAddFinding => {
                let kind = FindingKind::parse(
                    call.arg("kind")
                        .ok_or_else(|| AppError::Policy("missing finding kind".into()))?,
                )?;
                self.propose_finding_unlocked(
                    call.case_id(),
                    kind,
                    call.arg("value")
                        .ok_or_else(|| AppError::Policy("missing finding value".into()))?,
                    call.arg("evidence_hash")
                        .ok_or_else(|| AppError::Policy("missing finding evidence".into()))?,
                    "model",
                )?
                .into_bytes()
            }
            _ => return Err(AppError::Policy("invalid local tool".into())),
        })
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
        let raw = if local_tool {
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
                        .ok_or_else(|| AppError::Policy("external intel unavailable".into()))?
                        .execute(call, cancel).await?,
                    _ => return Err(AppError::Policy("invalid remote tool".into())),
                    })
                } => result,
            }
        };
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
            return Err(AppError::Policy("tool result exceeds 5 MB".into()));
        }
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
            .filter(|entry| matches!(entry.kind.as_str(), "Allowed" | "ToolDispatch"))
            .count())
    }

    pub(crate) fn siem_available(&self, source: Option<&str>) -> bool {
        source.is_some_and(|source| self.siems.iter().any(|port| port.source_id() == source))
    }

    pub(crate) async fn dispatch_siem(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let source = call
            .arg("source")
            .ok_or_else(|| AppError::Policy("missing SIEM source".into()))?;
        self.siems
            .iter()
            .find(|port| port.source_id() == source)
            .ok_or_else(|| AppError::Policy("SIEM source unavailable".into()))?
            .execute(call, cancel)
            .await
    }

    pub(crate) fn cloud_available(&self, source: Option<&str>) -> bool {
        source.is_some_and(|source| {
            self.cloud_audits
                .iter()
                .any(|port| port.source_id() == source)
        })
    }

    pub(crate) async fn dispatch_cloud(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let source = call
            .arg("source")
            .ok_or_else(|| AppError::Policy("missing cloud audit source".into()))?;
        self.cloud_audits
            .iter()
            .find(|port| port.source_id() == source)
            .ok_or_else(|| AppError::Policy("cloud audit source unavailable".into()))?
            .execute(call, cancel)
            .await
    }

    pub(crate) fn internal_intel_available(&self, source: Option<&str>) -> bool {
        source.is_some_and(|source| {
            self.internal_intel
                .iter()
                .any(|port| port.source_id() == source)
        })
    }

    pub(crate) fn edr_available(&self, source: Option<&str>, tool: &Tool) -> bool {
        source.is_some_and(|source| {
            self.edrs
                .iter()
                .any(|port| port.source_id() == source && port.supports(tool))
        })
    }

    pub(crate) async fn dispatch_edr(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let source = call
            .arg("source")
            .ok_or_else(|| AppError::Policy("missing EDR source".into()))?;
        let port = self
            .edrs
            .iter()
            .find(|port| port.source_id() == source && port.supports(call.tool()))
            .ok_or_else(|| AppError::Policy("EDR source unavailable".into()))?;
        port.execute(call, cancel).await
    }

    pub(crate) async fn dispatch_internal_intel(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let source = call
            .arg("source")
            .ok_or_else(|| AppError::Policy("missing internal intelligence source".into()))?;
        self.internal_intel
            .iter()
            .find(|port| port.source_id() == source)
            .ok_or_else(|| AppError::Policy("internal intelligence source unavailable".into()))?
            .execute(call, cancel)
            .await
    }
}
