use crate::{
    AuthorizedCall, Case, CaseScope, Decision, DomainError, ExecutionMode, PendingApproval,
    ProposedCall, Tainted,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyContext {
    pub tainted_arguments: bool,
    pub turn_has_detections: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RiskLevel {
    Read,
    Enrich,
    Contain,
}

/// Limits enforced in addition to the fixed risk rules. Unknown tools never become allowed.
#[derive(Clone, Debug)]
pub struct PolicyRules {
    pub denied_tools: Vec<Tool>,
    pub scope: Option<CaseScope>,
    pub max_tool_calls_per_case: usize,
    pub max_model_result_bytes: usize,
    pub max_model_tokens_per_case: u64,
}

impl Default for PolicyRules {
    fn default() -> Self {
        Self {
            denied_tools: Vec::new(),
            scope: None,
            max_tool_calls_per_case: 100,
            max_model_result_bytes: 10_000,
            max_model_tokens_per_case: 200_000,
        }
    }
}

impl PolicyRules {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.max_tool_calls_per_case == 0
            || self.max_tool_calls_per_case > 10_000
            || self.max_model_result_bytes == 0
            || self.max_model_result_bytes > 100_000
            || self.max_model_tokens_per_case == 0
            || self.max_model_tokens_per_case > 10_000_000
        {
            return Err(DomainError::InvalidPolicy);
        }
        if let Some(scope) = &self.scope {
            let CaseScope::Remote { version, .. } = scope else {
                return Err(DomainError::InvalidPolicy);
            };
            if !matches!(*version, 1 | 2)
                || scope
                    .to_v2_string()
                    .ok()
                    .and_then(|encoded| CaseScope::parse(&encoded).ok())
                    .is_none()
            {
                return Err(DomainError::InvalidPolicy);
            }
        }
        Ok(())
    }

    pub fn permits(&self, tool: &Tool, completed_calls: usize) -> Result<(), &'static str> {
        if self.denied_tools.contains(tool) {
            return Err("tool denied by policy");
        }
        if completed_calls >= self.max_tool_calls_per_case {
            return Err("case tool call quota reached");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Tool {
    EvidenceSearch,
    EvidenceRead,
    GraphSummary,
    EntityLookup,
    Neighbors,
    EntityTimeline,
    GraphPath,
    TextSearch,
    RawRecords,
    CaseAddFinding,
    SiemSearch,
    SiemGetAlert,
    CloudAuditEvents,
    CloudIdentity,
    EdrHostInfo,
    EdrProcessTree,
    EdrDetections,
    ThreatIntelInternal,
    ThreatIntelExternal,
}

mod dialect;
mod scope;
mod validation;
pub use dialect::{SplQueryClass, classify_spl_query};
use scope::{in_scope, scope_gate};
pub use validation::valid_entity;
use validation::valid_tool_arguments;

impl Tool {
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "evidence_search" => Ok(Self::EvidenceSearch),
            "evidence_read" => Ok(Self::EvidenceRead),
            "graph_summary" => Ok(Self::GraphSummary),
            "entity_lookup" => Ok(Self::EntityLookup),
            "neighbors" => Ok(Self::Neighbors),
            "entity_timeline" => Ok(Self::EntityTimeline),
            "path" | "graph_path" => Ok(Self::GraphPath),
            "text_search" => Ok(Self::TextSearch),
            "raw_records" => Ok(Self::RawRecords),
            "case_add_finding" => Ok(Self::CaseAddFinding),
            "siem_search" => Ok(Self::SiemSearch),
            "siem_get_alert" => Ok(Self::SiemGetAlert),
            "cloud_audit_events" => Ok(Self::CloudAuditEvents),
            "cloud_identity" => Ok(Self::CloudIdentity),
            "edr_host_info" => Ok(Self::EdrHostInfo),
            "edr_process_tree" => Ok(Self::EdrProcessTree),
            "edr_detections" => Ok(Self::EdrDetections),
            "ti_lookup_internal" => Ok(Self::ThreatIntelInternal),
            "ti_lookup_external" => Ok(Self::ThreatIntelExternal),
            _ => Err(DomainError::UnknownTool),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EvidenceSearch => "evidence_search",
            Self::EvidenceRead => "evidence_read",
            Self::GraphSummary => "graph_summary",
            Self::EntityLookup => "entity_lookup",
            Self::Neighbors => "neighbors",
            Self::EntityTimeline => "entity_timeline",
            Self::GraphPath => "path",
            Self::TextSearch => "text_search",
            Self::RawRecords => "raw_records",
            Self::CaseAddFinding => "case_add_finding",
            Self::SiemSearch => "siem_search",
            Self::SiemGetAlert => "siem_get_alert",
            Self::CloudAuditEvents => "cloud_audit_events",
            Self::CloudIdentity => "cloud_identity",
            Self::EdrHostInfo => "edr_host_info",
            Self::EdrProcessTree => "edr_process_tree",
            Self::EdrDetections => "edr_detections",
            Self::ThreatIntelInternal => "ti_lookup_internal",
            Self::ThreatIntelExternal => "ti_lookup_external",
        }
    }

    pub fn risk(&self) -> RiskLevel {
        match self {
            Self::ThreatIntelExternal => RiskLevel::Enrich,
            _ => RiskLevel::Read,
        }
    }
}

/// The call token can only be made here. Risk is derived from the tool, never model input.
pub fn evaluate(
    case: &Case,
    proposal: ProposedCall,
    decision_seq: u64,
    mode: ExecutionMode,
    now: u64,
) -> Decision {
    evaluate_with_context(
        case,
        proposal,
        decision_seq,
        mode,
        PolicyContext::default(),
        now,
    )
}

pub fn evaluate_tainted(
    case: &Case,
    proposal: Tainted<ProposedCall>,
    decision_seq: u64,
    mode: ExecutionMode,
    turn_has_detections: bool,
    now: u64,
) -> Decision {
    evaluate_with_context(
        case,
        proposal.value,
        decision_seq,
        mode,
        PolicyContext {
            tainted_arguments: true,
            turn_has_detections,
        },
        now,
    )
}

pub fn evaluate_tainted_with_rules(
    case: &Case,
    proposal: Tainted<ProposedCall>,
    decision_seq: u64,
    mode: ExecutionMode,
    turn_has_detections: bool,
    now: u64,
    rules: &PolicyRules,
) -> Decision {
    if rules
        .scope
        .as_ref()
        .is_some_and(|scope| !in_scope(scope, &proposal.value))
    {
        return Decision::Deny("outside organization policy scope");
    }
    evaluate_tainted(case, proposal, decision_seq, mode, turn_has_detections, now)
}

pub fn evaluate_with_rules(
    case: &Case,
    proposal: ProposedCall,
    decision_seq: u64,
    mode: ExecutionMode,
    now: u64,
    rules: &PolicyRules,
) -> Decision {
    if rules
        .scope
        .as_ref()
        .is_some_and(|scope| !in_scope(scope, &proposal))
    {
        return Decision::Deny("outside organization policy scope");
    }
    evaluate(case, proposal, decision_seq, mode, now)
}

pub fn evaluate_with_context(
    case: &Case,
    proposal: ProposedCall,
    decision_seq: u64,
    mode: ExecutionMode,
    context: PolicyContext,
    now: u64,
) -> Decision {
    if case.sealed {
        return Decision::Deny("case is sealed");
    }
    if !valid_tool_arguments(&proposal) {
        return Decision::Deny("invalid tool arguments");
    }
    for gate in [
        siem_gate(&proposal),
        scope_gate(case, &proposal),
        risk_gate(&proposal, mode, context),
    ] {
        match gate {
            Gate::Continue => {}
            Gate::Deny(reason) => return Decision::Deny(reason),
            Gate::Approval => {
                return Decision::NeedsApproval(PendingApproval::new(
                    case.id.clone(),
                    proposal,
                    decision_seq,
                    now,
                ));
            }
        }
    }
    Decision::Allow(AuthorizedCall {
        case_id: case.id.clone(),
        proposal,
        decision_seq,
    })
}

#[derive(Clone, Copy)]
pub(super) enum Gate {
    Continue,
    Deny(&'static str),
    Approval,
}

fn siem_gate(proposal: &ProposedCall) -> Gate {
    if proposal.tool != Tool::SiemSearch {
        return Gate::Continue;
    }
    match proposal
        .args
        .get("query")
        .map(|query| classify_spl_query(query))
    {
        Some(SplQueryClass::Forbidden) => Gate::Deny("SPL side-effect command is forbidden"),
        Some(SplQueryClass::Unparseable) => Gate::Approval,
        Some(SplQueryClass::SafeLiteral) => Gate::Continue,
        None => Gate::Deny("missing SIEM query"),
    }
}

fn risk_gate(proposal: &ProposedCall, mode: ExecutionMode, context: PolicyContext) -> Gate {
    match proposal.tool.risk() {
        RiskLevel::Contain => Gate::Deny("containment outside MVP"),
        RiskLevel::Enrich
            if context.tainted_arguments
                || context.turn_has_detections
                || mode == ExecutionMode::Unattended =>
        {
            Gate::Approval
        }
        RiskLevel::Enrich => Gate::Approval,
        RiskLevel::Read => Gate::Continue,
    }
}
