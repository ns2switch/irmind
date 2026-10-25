use crate::{
    AuthorizedCall, BTreeMap, Case, CaseScope, Decision, DomainError, ExecutionMode,
    PendingApproval, ProposedCall, Tainted, valid_scope_target, valid_scope_time,
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
    pub max_tool_calls_per_case: usize,
    pub max_model_result_bytes: usize,
    pub max_model_tokens_per_case: u64,
}

impl Default for PolicyRules {
    fn default() -> Self {
        Self {
            denied_tools: Vec::new(),
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
    CloudAuditEvents,
    CloudIdentity,
    EdrHostInfo,
    EdrProcessTree,
    EdrDetections,
    ThreatIntelInternal,
    ThreatIntelExternal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplQueryClass {
    SafeLiteral,
    Forbidden,
    Unparseable,
}

/// The MVP dialect is one literal term, never arbitrary SPL. The command list is
/// defense in depth so known side-effect commands are denied before approval.
pub fn classify_spl_query(query: &str) -> SplQueryClass {
    const FORBIDDEN: &[&str] = &[
        "outputlookup",
        "outputcsv",
        "collect",
        "sendemail",
        "sendalert",
        "script",
        "run",
        "rest",
        "map",
        "delete",
        "tscollect",
        "meventcollect",
    ];
    if query
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(|token| {
            FORBIDDEN
                .iter()
                .any(|command| token.eq_ignore_ascii_case(command))
        })
    {
        return SplQueryClass::Forbidden;
    }
    if !query.is_empty()
        && query.len() <= 128
        && query
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:@/".contains(&byte))
    {
        SplQueryClass::SafeLiteral
    } else {
        SplQueryClass::Unparseable
    }
}

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
    let valid = match proposal.tool {
        Tool::EvidenceSearch => {
            valid_args(&proposal.args, &["query", "limit"])
                && proposal
                    .args
                    .get("query")
                    .is_some_and(|q| !q.is_empty() && q.len() <= 256)
                && valid_limit(proposal.args.get("limit"))
        }
        Tool::EvidenceRead => {
            valid_args(&proposal.args, &["hash", "limit"])
                && proposal
                    .args
                    .get("hash")
                    .is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
                && valid_limit(proposal.args.get("limit"))
        }
        Tool::GraphSummary => proposal.args.is_empty(),
        Tool::EntityLookup => valid_entity_args(&proposal.args, false),
        Tool::Neighbors | Tool::EntityTimeline => valid_entity_args(&proposal.args, true),
        Tool::GraphPath => {
            valid_args(
                &proposal.args,
                &["from_kind", "from_value", "to_kind", "to_value"],
            ) && proposal
                .args
                .get("from_kind")
                .zip(proposal.args.get("from_value"))
                .is_some_and(|(kind, value)| valid_entity(kind, value))
                && proposal
                    .args
                    .get("to_kind")
                    .zip(proposal.args.get("to_value"))
                    .is_some_and(|(kind, value)| valid_entity(kind, value))
        }
        Tool::TextSearch => {
            valid_args(&proposal.args, &["query", "limit"])
                && proposal
                    .args
                    .get("query")
                    .is_some_and(|query| !query.trim().is_empty() && query.len() <= 128)
                && valid_limit(proposal.args.get("limit"))
        }
        Tool::RawRecords => {
            valid_args(&proposal.args, &["hash", "index"])
                && proposal.args.get("hash").is_some_and(|hash| {
                    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
                })
                && proposal
                    .args
                    .get("index")
                    .is_some_and(|index| index.parse::<usize>().is_ok_and(|index| index < 100_000))
        }
        Tool::CaseAddFinding => {
            valid_args(&proposal.args, &["kind", "value", "evidence_hash"])
                && proposal.args.get("kind").is_some_and(|kind| {
                    matches!(
                        kind.as_str(),
                        "ioc" | "hypothesis" | "technique" | "impact" | "recommendation"
                    )
                })
                && proposal.args.get("value").is_some_and(|value| {
                    !value.trim().is_empty() && value.len() <= 2_000 && !value.contains('\0')
                })
                && proposal.args.get("evidence_hash").is_some_and(|hash| {
                    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        }
        Tool::SiemSearch | Tool::CloudAuditEvents => {
            let query_key = if proposal.tool == Tool::SiemSearch {
                "query"
            } else {
                "event_name"
            };
            valid_args(
                &proposal.args,
                &["source", "account", "from", "to", query_key],
            ) && proposal
                .args
                .get("source")
                .is_some_and(|v| valid_scope_target(v))
                && proposal
                    .args
                    .get("account")
                    .is_some_and(|v| valid_scope_target(v))
                && proposal
                    .args
                    .get("from")
                    .is_some_and(|v| valid_scope_time(v))
                && proposal.args.get("to").is_some_and(|v| valid_scope_time(v))
                && proposal.args.get(query_key).is_some_and(|v| {
                    !v.is_empty()
                        && v.len()
                            <= if proposal.tool == Tool::SiemSearch {
                                1024
                            } else {
                                128
                            }
                        && !v.contains('\0')
                        && (proposal.tool == Tool::SiemSearch
                            || v.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || b"._-:@/".contains(&byte)
                            }))
                })
        }
        Tool::ThreatIntelInternal => {
            valid_args(&proposal.args, &["source", "ioc"])
                && proposal
                    .args
                    .get("source")
                    .is_some_and(|v| valid_scope_target(v))
                && proposal.args.get("ioc").is_some_and(|v| {
                    !v.is_empty()
                        && v.len() <= 253
                        && v.bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                })
        }
        Tool::CloudIdentity => {
            valid_args(&proposal.args, &["source", "account", "kind", "name"])
                && proposal
                    .args
                    .get("source")
                    .is_some_and(|value| valid_scope_target(value))
                && proposal
                    .args
                    .get("account")
                    .is_some_and(|value| valid_scope_target(value))
                && proposal
                    .args
                    .get("kind")
                    .is_some_and(|value| matches!(value.as_str(), "role" | "user"))
                && proposal.args.get("name").is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_+=,.@-".contains(&byte))
                })
        }
        Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections => {
            let fields: &[&str] = match proposal.tool {
                Tool::EdrHostInfo => &["source", "host"],
                Tool::EdrProcessTree => &["source", "host", "process_id"],
                Tool::EdrDetections => &["source", "host", "from", "to"],
                _ => &[],
            };
            valid_args(&proposal.args, fields)
                && proposal
                    .args
                    .get("source")
                    .is_some_and(|value| valid_scope_target(value))
                && proposal
                    .args
                    .get("host")
                    .is_some_and(|value| valid_scope_target(value))
                && (proposal.tool != Tool::EdrProcessTree
                    || proposal.args.get("process_id").is_some_and(|value| {
                        !value.is_empty()
                            && value.len() <= 128
                            && value
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                    }))
                && (proposal.tool != Tool::EdrDetections
                    || proposal
                        .args
                        .get("from")
                        .zip(proposal.args.get("to"))
                        .is_some_and(|(from, to)| valid_scope_time(from) && valid_scope_time(to)))
        }
        Tool::ThreatIntelExternal => {
            valid_args(&proposal.args, &["ioc"])
                && proposal
                    .args
                    .get("ioc")
                    .is_some_and(|v| !v.is_empty() && v.len() <= 253)
        }
    };
    if !valid {
        return Decision::Deny("invalid tool arguments");
    }
    if proposal.tool == Tool::SiemSearch {
        match proposal
            .args
            .get("query")
            .map(|query| classify_spl_query(query))
        {
            Some(SplQueryClass::Forbidden) => {
                return Decision::Deny("SPL side-effect command is forbidden");
            }
            Some(SplQueryClass::Unparseable) => {
                return Decision::NeedsApproval(PendingApproval::new(
                    case.id.clone(),
                    proposal,
                    decision_seq,
                    now,
                ));
            }
            Some(SplQueryClass::SafeLiteral) => {}
            None => return Decision::Deny("missing SIEM query"),
        }
    }
    if matches!(proposal.tool, Tool::SiemSearch | Tool::CloudAuditEvents) {
        let Ok(scope) = CaseScope::parse(&case.scope) else {
            return Decision::Deny("invalid case scope");
        };
        let in_scope = proposal
            .args
            .get("source")
            .zip(proposal.args.get("account"))
            .zip(proposal.args.get("from"))
            .zip(proposal.args.get("to"))
            .is_some_and(|(((source, account), from), to)| {
                scope.contains(source, Some(account), None, from, to)
            });
        if !in_scope {
            return Decision::NeedsApproval(PendingApproval::new(
                case.id.clone(),
                proposal,
                decision_seq,
                now,
            ));
        }
    }
    if proposal.tool == Tool::ThreatIntelInternal {
        let Ok(scope) = CaseScope::parse(&case.scope) else {
            return Decision::Deny("invalid case scope");
        };
        if !proposal
            .args
            .get("source")
            .is_some_and(|source| scope.allows_source(source))
        {
            return Decision::NeedsApproval(PendingApproval::new(
                case.id.clone(),
                proposal,
                decision_seq,
                now,
            ));
        }
    }
    if proposal.tool == Tool::CloudIdentity {
        let Ok(scope) = CaseScope::parse(&case.scope) else {
            return Decision::Deny("invalid case scope");
        };
        if !proposal
            .args
            .get("source")
            .zip(proposal.args.get("account"))
            .is_some_and(|(source, account)| scope.allows_account(source, account))
        {
            return Decision::NeedsApproval(PendingApproval::new(
                case.id.clone(),
                proposal,
                decision_seq,
                now,
            ));
        }
    }
    if matches!(
        proposal.tool,
        Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections
    ) {
        let Ok(scope) = CaseScope::parse(&case.scope) else {
            return Decision::Deny("invalid case scope");
        };
        let in_scope = proposal
            .args
            .get("source")
            .zip(proposal.args.get("host"))
            .is_some_and(|(source, host)| {
                if proposal.tool == Tool::EdrDetections {
                    proposal
                        .args
                        .get("from")
                        .zip(proposal.args.get("to"))
                        .is_some_and(|(from, to)| {
                            scope.contains(source, None, Some(host), from, to)
                        })
                } else {
                    scope.allows_host(source, host)
                }
            });
        if !in_scope {
            return Decision::NeedsApproval(PendingApproval::new(
                case.id.clone(),
                proposal,
                decision_seq,
                now,
            ));
        }
    }
    if proposal.tool.risk() == RiskLevel::Contain {
        return Decision::Deny("containment outside MVP");
    }
    if context.tainted_arguments && proposal.tool.risk() == RiskLevel::Enrich {
        return Decision::NeedsApproval(PendingApproval::new(
            case.id.clone(),
            proposal,
            decision_seq,
            now,
        ));
    }
    if context.turn_has_detections && proposal.tool.risk() != RiskLevel::Read {
        return Decision::NeedsApproval(PendingApproval::new(
            case.id.clone(),
            proposal,
            decision_seq,
            now,
        ));
    }
    if mode == ExecutionMode::Unattended && proposal.tool.risk() != RiskLevel::Read {
        return Decision::NeedsApproval(PendingApproval::new(
            case.id.clone(),
            proposal,
            decision_seq,
            now,
        ));
    }
    if proposal.tool.risk() == RiskLevel::Enrich {
        return Decision::NeedsApproval(PendingApproval::new(
            case.id.clone(),
            proposal,
            decision_seq,
            now,
        ));
    }
    Decision::Allow(AuthorizedCall {
        case_id: case.id.clone(),
        proposal,
        decision_seq,
    })
}

fn valid_args(args: &BTreeMap<String, String>, allowed: &[&str]) -> bool {
    args.keys().all(|key| allowed.contains(&key.as_str()))
}

fn valid_limit(value: Option<&String>) -> bool {
    value.is_none_or(|v| v.parse::<usize>().is_ok_and(|n| (1..=20).contains(&n)))
}

fn valid_entity_args(args: &BTreeMap<String, String>, allow_limit: bool) -> bool {
    let fields: &[&str] = if allow_limit {
        &["kind", "value", "limit"]
    } else {
        &["kind", "value"]
    };
    valid_args(args, fields)
        && args
            .get("kind")
            .zip(args.get("value"))
            .is_some_and(|(kind, value)| valid_entity(kind, value))
        && valid_limit(args.get("limit"))
}

pub fn valid_entity(kind: &str, value: &str) -> bool {
    matches!(
        kind,
        "ip" | "host" | "user" | "role" | "identity" | "domain" | "hash" | "account" | "key"
    ) && !value.is_empty()
        && value.len() <= 512
}
