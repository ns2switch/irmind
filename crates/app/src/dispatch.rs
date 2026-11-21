mod execution;
pub(crate) mod listing;
mod local;
pub(crate) mod object_read;
mod original;
mod remote;
mod result_source;

use crate::{
    AppError, AuditEventKind, AuthorizedCall, BTreeMap, CancellationToken, Case, CaseId, Decision,
    Engine, PendingApproval, ProposedCall, Provenance, Screened, SourceKind, Tainted, Tool, hex,
    remote_tool_error, sha256,
};

#[derive(Clone)]
pub(crate) struct ToolFeedback {
    pub(crate) text: String,
    pub(crate) source_query_limit: Option<crate::source_queries::SourceQueryLimitNotice>,
}

impl From<String> for ToolFeedback {
    fn from(text: String) -> Self {
        Self {
            text,
            source_query_limit: None,
        }
    }
}
impl From<&str> for ToolFeedback {
    fn from(text: &str) -> Self {
        text.to_owned().into()
    }
}

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
        let case_lock = self
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
        let _case_lock = if proposal.tool == Tool::SourceQuery {
            drop(case_lock);
            None
        } else {
            Some(case_lock)
        };
        self.execute_proposal_from_origin(&case, proposal, crate::AuditOrigin::Analyst, cancel)
            .await
            .map(|feedback| {
                if let Some(notice) = feedback.source_query_limit {
                    format!("{}\n{}", notice.message(), feedback.text)
                } else {
                    feedback.text
                }
            })
    }

    pub(crate) async fn execute_proposal(
        &self,
        case: &Case,
        proposal: ProposedCall,
        cancel: &CancellationToken,
    ) -> Result<ToolFeedback, AppError> {
        self.execute_proposal_from_origin(case, proposal, crate::AuditOrigin::Model, cancel)
            .await
    }

    async fn execute_proposal_from_origin(
        &self,
        case: &Case,
        proposal: ProposedCall,
        origin: crate::AuditOrigin,
        cancel: &CancellationToken,
    ) -> Result<ToolFeedback, AppError> {
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
                if reason == "case tool call quota reached" {
                    let owned = id.clone();
                    return self
                        .blocking_local(move |local| {
                            Ok(format!(
                                "denied: {reason}. {}",
                                local
                                    .case_budget_unlocked(&owned)?
                                    .notice("case tool call limit")
                            )
                            .into())
                        })
                        .await;
                }
                Ok(format!("denied: {reason}").into())
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
                    return Ok(format!("denied: {reason}").into());
                }
                let id_owned = id.clone();
                let mode = self.mode;
                let challenge_id = self
                    .blocking_local(move |local| local.audit_pending(&id_owned, &pending, mode))
                    .await?;
                Ok(format!("approval pending: {challenge_id}; request was not executed").into())
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
                    return Ok(format!("denied: {reason}").into());
                }
                let (screened, hash) = self.execute_authorized(id, &call, false, cancel).await?;
                let source_query_limit = self
                    .query_limit_for_tool_result(id, call.tool(), hash, cancel)
                    .await?;
                Ok(ToolFeedback {
                    text: screened,
                    source_query_limit,
                })
            }
        }
    }

    async fn query_limit_for_tool_result(
        &self,
        id: &CaseId,
        tool: &Tool,
        hash: String,
        cancel: &CancellationToken,
    ) -> Result<Option<crate::source_queries::SourceQueryLimitNotice>, AppError> {
        if tool != &Tool::SourceQuery || hash.is_empty() {
            return Ok(None);
        }
        let case = id.clone();
        let cancel = cancel.clone();
        self.blocking_local(move |local| {
            let _lock = local.repo.lock_case(&case)?;
            let entries = local.audit_log.entries(&case)?;
            local.verify_source_query_journal(&entries, &cancel, false)?;
            let notices = crate::source_queries::result_limit_notices(&entries)?;
            Ok(notices
                .into_iter()
                .find(|notice| notice.capture_sha256() == hash))
        })
        .await
    }

    pub(crate) async fn evaluate_proposal(
        &self,
        case: &Case,
        proposal: ProposedCall,
        origin: crate::AuditOrigin,
    ) -> Result<Decision, AppError> {
        let proposal_payload = format!("{} {:?}", proposal.tool.as_str(), proposal.args);
        let case_owned = case.clone();
        self.blocking_local(move |local| {
            let id = &case_owned.id;
            let current = local.repo.get_case(id)?;
            if current.sealed {
                return Ok(Decision::Deny("case is sealed"));
            }
            if proposal.tool == Tool::SourceQuery
                && crate::source_queries::SourceQueryV1::from_proposal(&proposal.args).is_err()
            {
                return Ok(Decision::Deny(
                    "source query arguments must match the bounded structured schema",
                ));
            }
            let policy = local.policy_for_case_unlocked(id)?;
            local.audit(
                id,
                origin,
                irmind_domain::AuditEventKind::Proposal,
                &proposal_payload,
                None,
            )?;
            let completed_calls = local.completed_calls_unlocked(id)?;
            if let Err(reason) = policy.permits(&proposal.tool, completed_calls) {
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
                    &current,
                    tainted,
                    next_seq,
                    local.mode,
                    local.turn_has_detections(id)?,
                    now,
                    &policy,
                ))
            } else {
                Ok(irmind_domain::evaluate_with_rules(
                    &current, proposal, next_seq, local.mode, now, &policy,
                ))
            }
        })
        .await
    }

    pub(crate) fn unavailable_reason(&self, call: &AuthorizedCall) -> Option<&'static str> {
        if call.tool() == &Tool::DelegateTask {
            return Some("delegation is available only inside an attended model turn");
        }
        self.source_unavailable_reason(call.tool(), call.arg("source"))
            .or_else(|| {
                (call.tool() == &Tool::ThreatIntelExternal && self.threat_intel.is_none())
                    .then_some("external intelligence module unavailable")
            })
    }

    fn pending_unavailable_reason(&self, pending: &PendingApproval) -> Option<&'static str> {
        if pending.proposal().tool == Tool::SourceQuery {
            return Some("case policy denied source-query preflight");
        }
        self.source_unavailable_reason(
            &pending.proposal().tool,
            pending.proposal().args.get("source").map(String::as_str),
        )
    }

    fn source_unavailable_reason(&self, tool: &Tool, source: Option<&str>) -> Option<&'static str> {
        match tool {
            Tool::SourceQuery
                if !source.is_some_and(|source| {
                    self.source_queries
                        .as_ref()
                        .is_some_and(|ports| ports.available_source(source))
                }) =>
            {
                Some("source queries require a configured source-query module")
            }
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
            Tool::ObjectRead
                if self.large_case_store.is_none() || self.streaming_parser.is_none() =>
            {
                Some("large case pipeline unavailable")
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
        let recorded = self
            .audit_log
            .entries(id)?
            .iter()
            .filter(|entry| {
                matches!(
                    entry.kind,
                    AuditEventKind::Allowed | AuditEventKind::ToolDispatch
                )
            })
            .count();
        let held = usize::try_from(self.subagent_holds_unlocked(id)?.calls)
            .map_err(|_| AppError::InvalidChain(0))?;
        recorded.checked_add(held).ok_or(AppError::InvalidChain(0))
    }
}
