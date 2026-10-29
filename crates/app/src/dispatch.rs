mod execution;
mod local;
mod remote;

use crate::{
    AppError, AuditEventKind, AuthorizedCall, BTreeMap, CancellationToken, Case, CaseId, Decision,
    Engine, PendingApproval, ProposedCall, Provenance, Screened, SourceKind, Tainted, Tool, hex,
    remote_tool_error, sha256,
};

impl Engine<'_> {
    pub fn request_tool_as_analyst(
        &self,
        id: &CaseId,
        proposal: ProposedCall,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        crate::run_async(self.request_tool_as_analyst_cancelable(id, proposal, cancel))
    }

    pub async fn request_tool_as_analyst_cancelable(
        &self,
        id: &CaseId,
        proposal: ProposedCall,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if self.mode != irmind_domain::ExecutionMode::Attended
            || self.signer.actor() != irmind_domain::Actor::Analyst
        {
            return Err(AppError::Policy(
                "manual tool request requires an attended analyst".into(),
            ));
        }
        let id_owned = id.clone();
        let _case_lock = self
            .blocking_local(move |local| local.repo.lock_case(&id_owned))
            .await?;
        let id_owned = id.clone();
        let local_cancel = cancel.clone();
        let case = self
            .blocking_local(move |local| {
                local.verify_unlocked_cancelable(&id_owned, &local_cancel)?;
                local.repo.get_case(&id_owned)
            })
            .await?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.execute_proposal_from_origin(&case, proposal, crate::AuditOrigin::Analyst, cancel)
            .await
    }

    pub(crate) async fn execute_proposal(
        &self,
        case: &Case,
        proposal: ProposedCall,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.execute_proposal_from_origin(case, proposal, crate::AuditOrigin::Model, cancel)
            .await
    }

    async fn execute_proposal_from_origin(
        &self,
        case: &Case,
        proposal: ProposedCall,
        origin: crate::AuditOrigin,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let id = &case.id;
        let decision = self.evaluate_proposal(case, proposal, origin).await?;
        match decision {
            Decision::Deny(reason) => {
                self.audit_local(
                    id,
                    crate::AuditOrigin::Policy,
                    AuditEventKind::Denied,
                    reason,
                    None,
                )
                .await?;
                Ok(format!("denied: {reason}"))
            }
            Decision::NeedsApproval(pending) => {
                if let Some(reason) = self.pending_unavailable_reason(&pending) {
                    self.audit_local(
                        id,
                        crate::AuditOrigin::Policy,
                        AuditEventKind::Denied,
                        reason,
                        None,
                    )
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
                    self.audit_local(
                        id,
                        crate::AuditOrigin::Policy,
                        AuditEventKind::Denied,
                        reason,
                        None,
                    )
                    .await?;
                    return Ok(format!("denied: {reason}"));
                }
                let (screened, _) = self.execute_authorized(id, &call, false, cancel).await?;
                Ok(screened)
            }
        }
    }

    async fn evaluate_proposal(
        &self,
        case: &Case,
        proposal: ProposedCall,
        origin: crate::AuditOrigin,
    ) -> Result<Decision, AppError> {
        let proposal_payload = format!("{} {:?}", proposal.tool.as_str(), proposal.args);
        let case_owned = case.clone();
        self.blocking_local(move |local| {
            let id = &case_owned.id;
            local.audit(
                id,
                origin,
                irmind_domain::AuditEventKind::Proposal,
                &proposal_payload,
                None,
            )?;
            let completed_calls = local.completed_calls_unlocked(id)?;
            if let Err(reason) = local.policy.permits(&proposal.tool, completed_calls) {
                return Ok(Decision::Deny(reason));
            }
            let next_seq = local
                .audit_log
                .last_entry(id)?
                .map_or(1, |entry| entry.seq + 1);
            let now = local.clock.now()?;
            if origin == crate::AuditOrigin::Model {
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
                    now,
                    &local.policy,
                ))
            } else {
                Ok(irmind_domain::evaluate_with_rules(
                    &case_owned,
                    proposal,
                    next_seq,
                    local.mode,
                    now,
                    &local.policy,
                ))
            }
        })
        .await
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
            Tool::SiemSearch | Tool::SiemGetAlert if !self.siem_available(source) => {
                Some("SIEM source unavailable")
            }
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
            Tool::ObjectList | Tool::ObjectRead if !self.object_source_available(source) => {
                Some("object source unavailable")
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

    pub fn screen_and_audit(
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
                crate::AuditOrigin::Guard,
                irmind_domain::AuditEventKind::InjectionDetected,
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
            self.audit(
                id,
                crate::AuditOrigin::Guard,
                irmind_domain::AuditEventKind::BinaryResultOmitted,
                source,
                evidence,
            )?;
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
