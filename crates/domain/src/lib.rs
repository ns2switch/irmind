#![forbid(unsafe_code)]

use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CaseId(String);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AgentId(String);

impl AgentId {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(DomainError::InvalidId);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Actor {
    Analyst,
    Agent(AgentId),
}

impl Actor {
    pub fn as_storage(&self) -> String {
        match self {
            Self::Analyst => "analyst".into(),
            Self::Agent(id) => format!("agent:{}", id.as_str()),
        }
    }
    pub fn parse_storage(value: &str) -> Result<Self, DomainError> {
        if value == "analyst" {
            return Ok(Self::Analyst);
        }
        value
            .strip_prefix("agent:")
            .map(AgentId::parse)
            .transpose()?
            .map(Self::Agent)
            .ok_or(DomainError::InvalidId)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    Attended,
    Unattended,
}

/// Data that originated outside the trusted case and policy boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct Tainted<T> {
    value: T,
    provenance: Provenance,
}

impl<T> std::fmt::Debug for Tainted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tainted")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    File,
    ToolResult,
    Graph,
    ModelProposal,
    AnalystInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    evidence_hash: [u8; 32],
    record_index: Option<u64>,
    source_kind: SourceKind,
}

impl Provenance {
    pub fn new(
        evidence_hash: [u8; 32],
        record_index: Option<u64>,
        source_kind: SourceKind,
    ) -> Self {
        Self {
            evidence_hash,
            record_index,
            source_kind,
        }
    }

    pub fn evidence_hash(&self) -> &[u8; 32] {
        &self.evidence_hash
    }
    pub fn record_index(&self) -> Option<u64> {
        self.record_index
    }
    pub fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    pub fn approval_challenge(&self, case_id: &CaseId) -> Vec<u8> {
        let mut out = b"irmind-declassify-v1\0".to_vec();
        out.extend_from_slice(case_id.as_str().as_bytes());
        out.push(0);
        out.extend_from_slice(&self.evidence_hash);
        out.extend_from_slice(&self.record_index.unwrap_or(u64::MAX).to_be_bytes());
        out.push(self.source_kind as u8);
        out
    }
}

pub trait DeclassificationAuthority {
    fn verify_and_audit(&self, challenge: &[u8], signature: &[u8], provenance: &Provenance)
    -> bool;
}

impl<T> Tainted<T> {
    pub fn from_external(value: T, provenance: Provenance) -> Self {
        Self { value, provenance }
    }

    /// Permits local processing without returning an untainted value.
    pub fn inspect(&self, visitor: impl FnOnce(&T)) {
        visitor(&self.value);
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub fn release_with_approval(
        self,
        case_id: &CaseId,
        signature: &[u8],
        authority: &dyn DeclassificationAuthority,
    ) -> Result<T, DomainError> {
        let challenge = self.provenance.approval_challenge(case_id);
        if !authority.verify_and_audit(&challenge, signature, &self.provenance) {
            return Err(DomainError::InvalidApproval);
        }
        Ok(self.value)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyContext {
    pub tainted_arguments: bool,
    pub turn_has_detections: bool,
}

impl CaseId {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.len() != 36 || !value.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return Err(DomainError::InvalidId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct Case {
    pub id: CaseId,
    pub title: String,
    pub severity: Severity,
    pub scope: String,
    pub sealed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(DomainError::InvalidSeverity),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Explicit remote scope. Free-form legacy scope text is always local-only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseScope {
    LocalOnly,
    Remote {
        sources: BTreeSet<String>,
        accounts: BTreeSet<String>,
        hosts: BTreeSet<String>,
        from: String,
        to: String,
    },
}

impl CaseScope {
    /// Format: v1;sources=source1,source2;accounts=id1;hosts=host1;from=...Z;to=...Z.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let Some(rest) = value.strip_prefix("v1;") else {
            return Ok(Self::LocalOnly);
        };
        let parts = rest.split(';').collect::<Vec<_>>();
        if parts.len() != 5 {
            return Err(DomainError::InvalidScope);
        }
        let fields = parts
            .iter()
            .map(|part| part.split_once('=').ok_or(DomainError::InvalidScope))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if fields.len() != 5
            || fields
                .keys()
                .any(|key| !matches!(*key, "sources" | "accounts" | "hosts" | "from" | "to"))
        {
            return Err(DomainError::InvalidScope);
        }
        let sources = parse_scope_set(fields.get("sources").ok_or(DomainError::InvalidScope)?)?;
        let accounts = parse_scope_set(fields.get("accounts").ok_or(DomainError::InvalidScope)?)?;
        let hosts = parse_scope_set(fields.get("hosts").ok_or(DomainError::InvalidScope)?)?;
        let from = *fields.get("from").ok_or(DomainError::InvalidScope)?;
        let to = *fields.get("to").ok_or(DomainError::InvalidScope)?;
        if sources.is_empty()
            || (accounts.is_empty() && hosts.is_empty())
            || !valid_scope_time(from)
            || !valid_scope_time(to)
            || from > to
        {
            return Err(DomainError::InvalidScope);
        }
        Ok(Self::Remote {
            sources,
            accounts,
            hosts,
            from: from.to_owned(),
            to: to.to_owned(),
        })
    }

    pub fn contains(
        &self,
        source: &str,
        account: Option<&str>,
        host: Option<&str>,
        from: &str,
        to: &str,
    ) -> bool {
        let Self::Remote {
            sources,
            accounts,
            hosts,
            from: scope_from,
            to: scope_to,
        } = self
        else {
            return false;
        };
        sources.contains(source)
            && match account {
                Some(value) => accounts.contains(value),
                None => accounts.is_empty(),
            }
            && match host {
                Some(value) => hosts.contains(value),
                None => hosts.is_empty(),
            }
            && valid_scope_time(from)
            && valid_scope_time(to)
            && from <= to
            && from >= scope_from.as_str()
            && to <= scope_to.as_str()
    }

    pub fn allows_source(&self, source: &str) -> bool {
        match self {
            Self::LocalOnly => false,
            Self::Remote { sources, .. } => sources.contains(source),
        }
    }

    pub fn allows_account(&self, source: &str, account: &str) -> bool {
        match self {
            Self::LocalOnly => false,
            Self::Remote {
                sources,
                accounts,
                hosts,
                ..
            } => sources.contains(source) && accounts.contains(account) && hosts.is_empty(),
        }
    }

    pub fn allows_host(&self, source: &str, host: &str) -> bool {
        match self {
            Self::LocalOnly => false,
            Self::Remote {
                sources,
                accounts,
                hosts,
                ..
            } => sources.contains(source) && hosts.contains(host) && accounts.is_empty(),
        }
    }
}

fn parse_scope_set(value: &str) -> Result<BTreeSet<String>, DomainError> {
    if value.is_empty() {
        return Ok(BTreeSet::new());
    }
    let values = value.split(',').collect::<Vec<_>>();
    if values.len() > 32 || values.iter().any(|item| !valid_scope_target(item)) {
        return Err(DomainError::InvalidScope);
    }
    let set = values
        .iter()
        .map(|item| (*item).to_owned())
        .collect::<BTreeSet<_>>();
    if set.len() != values.len() {
        return Err(DomainError::InvalidScope);
    }
    Ok(set)
}

fn valid_scope_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:/".contains(&byte))
}

fn valid_scope_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
        && {
            let number = |range: std::ops::Range<usize>| {
                value.get(range).and_then(|part| part.parse::<u32>().ok())
            };
            let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
                number(0..4),
                number(5..7),
                number(8..10),
                number(11..13),
                number(14..16),
                number(17..19),
            ) else {
                return false;
            };
            let leap =
                year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
            let max_day = match month {
                2 if leap => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                _ => 0,
            };
            year > 0 && (1..=max_day).contains(&day) && hour < 24 && minute < 60 && second < 60
        }
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

#[derive(Clone)]
pub struct ProposedCall {
    pub tool: Tool,
    pub args: BTreeMap<String, String>,
}

impl std::fmt::Debug for ProposedCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProposedCall")
            .field("tool", &self.tool)
            .field("argument_count", &self.args.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizedCall {
    case_id: CaseId,
    proposal: ProposedCall,
    decision_seq: u64,
}

impl AuthorizedCall {
    pub fn case_id(&self) -> &CaseId {
        &self.case_id
    }
    pub fn tool(&self) -> &Tool {
        &self.proposal.tool
    }
    pub fn arg(&self, key: &str) -> Option<&str> {
        self.proposal.args.get(key).map(String::as_str)
    }
    pub fn proposal_args(&self) -> &BTreeMap<String, String> {
        &self.proposal.args
    }
    pub fn decision_seq(&self) -> u64 {
        self.decision_seq
    }
}

#[derive(Debug)]
pub enum Decision {
    Allow(AuthorizedCall),
    Deny(&'static str),
    NeedsApproval(PendingApproval),
}

#[derive(Debug)]
pub struct PendingApproval {
    case_id: CaseId,
    proposal: ProposedCall,
    decision_seq: u64,
    expires_at: u64,
}

pub trait AnalystApprovalVerifier {
    fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool;
}

impl PendingApproval {
    fn new(case_id: CaseId, proposal: ProposedCall, decision_seq: u64, now: u64) -> Self {
        let expires_at = now.saturating_add(300);
        Self {
            case_id,
            proposal,
            decision_seq,
            expires_at,
        }
    }

    pub fn recover(
        case: &Case,
        mode: ExecutionMode,
        encoded: &[u8],
        now: u64,
    ) -> Result<Self, DomainError> {
        let mut rest = encoded
            .strip_prefix(b"irmind-approval-v2\0")
            .ok_or(DomainError::InvalidApproval)?;
        let case_id = std::str::from_utf8(take_field(&mut rest)?)
            .map_err(|_| DomainError::InvalidApproval)?;
        if case_id != case.id.as_str() {
            return Err(DomainError::InvalidApproval);
        }
        let decision_seq = take_u64(&mut rest)?;
        let name = std::str::from_utf8(take_field(&mut rest)?)
            .map_err(|_| DomainError::InvalidApproval)?;
        let tool = Tool::parse(name)?;
        let count = take_u64(&mut rest)?;
        if count > 16 {
            return Err(DomainError::InvalidApproval);
        }
        let mut args = BTreeMap::new();
        for _ in 0..count {
            let key = std::str::from_utf8(take_field(&mut rest)?)
                .map_err(|_| DomainError::InvalidApproval)?;
            let value = std::str::from_utf8(take_field(&mut rest)?)
                .map_err(|_| DomainError::InvalidApproval)?;
            if key.len() > 64
                || value.len() > 1024
                || args.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err(DomainError::InvalidApproval);
            }
        }
        let claimed_hash = rest.get(..32).ok_or(DomainError::InvalidApproval)?;
        if claimed_hash != Sha256::digest(canonical_args(&args)).as_slice() {
            return Err(DomainError::InvalidApproval);
        }
        rest = &rest[32..];
        let expires_at = take_u64(&mut rest)?;
        if !rest.is_empty() {
            return Err(DomainError::InvalidApproval);
        }
        let mut open = case.clone();
        open.sealed = false;
        let Decision::NeedsApproval(mut pending) =
            evaluate(&open, ProposedCall { tool, args }, decision_seq, mode, now)
        else {
            return Err(DomainError::InvalidApproval);
        };
        pending.expires_at = expires_at;
        if pending.challenge() != encoded {
            return Err(DomainError::InvalidApproval);
        }
        Ok(pending)
    }
    pub fn proposal(&self) -> &ProposedCall {
        &self.proposal
    }

    pub fn decision_seq(&self) -> u64 {
        self.decision_seq
    }

    pub fn challenge(&self) -> Vec<u8> {
        let mut bytes = b"irmind-approval-v2\0".to_vec();
        put(&mut bytes, self.case_id.as_str().as_bytes());
        bytes.extend_from_slice(&self.decision_seq.to_be_bytes());
        put(&mut bytes, self.proposal.tool.as_str().as_bytes());
        let args = canonical_args(&self.proposal.args);
        bytes.extend_from_slice(&args);
        bytes.extend_from_slice(&Sha256::digest(&args));
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes
    }

    pub fn resolve(
        self,
        signature: &[u8],
        verifier: &dyn AnalystApprovalVerifier,
        now: u64,
    ) -> Result<AuthorizedCall, DomainError> {
        if now > self.expires_at || !verifier.verify_analyst(&self.challenge(), signature) {
            return Err(DomainError::InvalidApproval);
        }
        Ok(AuthorizedCall {
            case_id: self.case_id,
            proposal: self.proposal,
            decision_seq: self.decision_seq,
        })
    }

    pub fn rejection_challenge(&self) -> Vec<u8> {
        let mut bytes = self.challenge();
        bytes.extend_from_slice(b"\0deny");
        bytes
    }

    pub fn reject(
        self,
        signature: &[u8],
        verifier: &dyn AnalystApprovalVerifier,
    ) -> Result<(), DomainError> {
        if !verifier.verify_analyst(&self.rejection_challenge(), signature) {
            return Err(DomainError::InvalidApproval);
        }
        Ok(())
    }
}

fn canonical_args(args: &BTreeMap<String, String>) -> Vec<u8> {
    let mut bytes = (args.len() as u64).to_be_bytes().to_vec();
    for (key, value) in args {
        put(&mut bytes, key.as_bytes());
        put(&mut bytes, value.as_bytes());
    }
    bytes
}

fn put(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn take_u64(rest: &mut &[u8]) -> Result<u64, DomainError> {
    let Some(bytes) = rest.get(..8) else {
        return Err(DomainError::InvalidApproval);
    };
    let number = u64::from_be_bytes(bytes.try_into().map_err(|_| DomainError::InvalidApproval)?);
    *rest = &rest[8..];
    Ok(number)
}

fn take_field<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], DomainError> {
    let length = usize::try_from(take_u64(rest)?).map_err(|_| DomainError::InvalidApproval)?;
    if length > 2048 {
        return Err(DomainError::InvalidApproval);
    }
    let Some(value) = rest.get(..length) else {
        return Err(DomainError::InvalidApproval);
    };
    *rest = &rest[length..];
    Ok(value)
}

#[derive(Debug, Eq, PartialEq)]
pub enum DomainError {
    InvalidId,
    UnknownTool,
    InvalidApproval,
    InvalidPolicy,
    InvalidScope,
    InvalidSeverity,
}

/// Deterministic entity extraction from known structured log fields.
pub fn classify_field(key: &str, value: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    if value.is_empty() || value.len() > 512 {
        return None;
    }
    if key.contains("ipaddress") || key == "ip" || key.ends_with("_ip") {
        return Some("ip");
    }
    if key.contains("hostname") || key == "host" || key.ends_with("_host") {
        return Some("host");
    }
    if key.contains("username") || key == "user" || key == "principalid" {
        return Some("user");
    }
    if key == "arn" {
        return Some(if value.contains(":role/") {
            "role"
        } else {
            "identity"
        });
    }
    if key.contains("domain") {
        return Some("domain");
    }
    if key.contains("sha256") || key.contains("sha1") || key == "md5" {
        return Some("hash");
    }
    if key == "accesskeyid" {
        return Some("key");
    }
    if key.contains("accountid") {
        return Some("account");
    }
    None
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn debug_of_tainted_and_proposed_values_is_redacted() {
        let tainted = Tainted::from_external(
            "SECRET-from-log".to_owned(),
            Provenance::new([0; 32], Some(3), SourceKind::File),
        );
        assert!(!format!("{tainted:?}").contains("SECRET"));
        let proposal = ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "SECRET-from-log".into())]),
        };
        assert!(!format!("{proposal:?}").contains("SECRET"));
    }

    fn case() -> Case {
        Case {
            id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            title: "x".into(),
            severity: Severity::Medium,
            scope: "local".into(),
            sealed: false,
        }
    }

    #[test]
    fn unknown_arguments_fail_closed() {
        let proposal = ProposedCall {
            tool: Tool::EvidenceSearch,
            args: BTreeMap::from([
                ("query".into(), "test".into()),
                ("send_to".into(), "outside".into()),
            ]),
        };
        assert!(matches!(
            evaluate(&case(), proposal, 1, ExecutionMode::Attended, 1_700_000_000),
            Decision::Deny(_)
        ));
    }

    #[test]
    #[allow(clippy::panic)]
    fn spl_commands_are_denied_and_unparseable_queries_need_exact_approval() {
        let mut scoped = case();
        scoped.scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        let proposal = |query: &str| ProposedCall {
            tool: Tool::SiemSearch,
            args: BTreeMap::from([
                ("source".into(), "splunk-prod".into()),
                ("account".into(), "123".into()),
                ("from".into(), "2026-10-23T12:00:00Z".into()),
                ("to".into(), "2026-10-23T13:00:00Z".into()),
                ("query".into(), query.into()),
            ]),
        };
        for command in [
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
        ] {
            assert_eq!(
                classify_spl_query(&format!("event | {command} target")),
                SplQueryClass::Forbidden
            );
            assert!(matches!(
                evaluate(
                    &scoped,
                    proposal(&format!("event | {command} target")),
                    1,
                    ExecutionMode::Attended,
                    1_700_000_000
                ),
                Decision::Deny(_)
            ));
        }
        let exact = "event | stats count";
        let Decision::NeedsApproval(pending) = evaluate(
            &scoped,
            proposal(exact),
            2,
            ExecutionMode::Attended,
            1_700_000_000,
        ) else {
            panic!("expected approval")
        };
        assert_eq!(
            pending.proposal().args.get("query").map(String::as_str),
            Some(exact)
        );
        assert!(matches!(
            evaluate(
                &scoped,
                proposal("AssumeRole"),
                3,
                ExecutionMode::Attended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
    }

    #[test]
    fn external_lookup_requires_approval() {
        let proposal = ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "example.com".into())]),
        };
        assert!(matches!(
            evaluate(&case(), proposal, 1, ExecutionMode::Attended, 1_700_000_000),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    #[allow(clippy::panic)]
    fn approval_signature_binds_case_arguments_sequence_and_expiry() {
        struct ExactChallenge(Vec<u8>);
        impl AnalystApprovalVerifier for ExactChallenge {
            fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool {
                message == self.0 && signature == self.0
            }
        }
        let proposal = |ioc: &str| ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), ioc.into())]),
        };
        let Decision::NeedsApproval(first) = evaluate(
            &case(),
            proposal("example.com"),
            7,
            ExecutionMode::Attended,
            1_700_000_000,
        ) else {
            panic!("expected pending approval")
        };
        let signed = first.challenge();
        let verifier = ExactChallenge(signed.clone());
        assert!(first.resolve(&signed, &verifier, 1_700_000_000).is_ok());

        let mut other_case = case();
        other_case.id = CaseId::parse("00000000-0000-0000-0000-000000000002").unwrap();
        let Decision::NeedsApproval(other) = evaluate(
            &other_case,
            proposal("example.com"),
            7,
            ExecutionMode::Attended,
            1_700_000_000,
        ) else {
            panic!("expected pending approval")
        };
        assert!(other.resolve(&signed, &verifier, 1_700_000_000).is_err());
        let Decision::NeedsApproval(other_args) = evaluate(
            &case(),
            proposal("other.example"),
            7,
            ExecutionMode::Attended,
            1_700_000_000,
        ) else {
            panic!("expected pending approval")
        };
        assert!(
            other_args
                .resolve(&signed, &verifier, 1_700_000_000)
                .is_err()
        );
        let Decision::NeedsApproval(other_seq) = evaluate(
            &case(),
            proposal("example.com"),
            8,
            ExecutionMode::Attended,
            1_700_000_000,
        ) else {
            panic!("expected pending approval")
        };
        assert!(
            other_seq
                .resolve(&signed, &verifier, 1_700_000_000)
                .is_err()
        );
        let before =
            PendingApproval::recover(&case(), ExecutionMode::Attended, &signed, 1_700_000_000)
                .unwrap();
        assert!(before.resolve(&signed, &verifier, 1_700_000_299).is_ok());
        let after =
            PendingApproval::recover(&case(), ExecutionMode::Attended, &signed, 1_700_000_000)
                .unwrap();
        assert!(after.resolve(&signed, &verifier, 1_700_000_301).is_err());
        assert!(!signed.starts_with(b"irmind-audit-v2\0"));
        assert!(!signed.starts_with(b"irmind-seal-v1\0"));
    }

    #[test]
    fn policy_limits_cannot_enable_a_denied_tool_or_exceed_quota() {
        let rules = PolicyRules {
            denied_tools: vec![Tool::ThreatIntelExternal],
            max_tool_calls_per_case: 2,
            max_model_result_bytes: 100,
            max_model_tokens_per_case: 200,
        };
        assert!(rules.validate().is_ok());
        assert!(rules.permits(&Tool::ThreatIntelExternal, 0).is_err());
        assert!(rules.permits(&Tool::EvidenceSearch, 1).is_ok());
        assert!(rules.permits(&Tool::EvidenceSearch, 2).is_err());
        assert!(matches!(
            evaluate(
                &case(),
                ProposedCall {
                    tool: Tool::ThreatIntelExternal,
                    args: BTreeMap::from([("ioc".into(), "example.com".into())]),
                },
                1,
                ExecutionMode::Attended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    fn remote_scope_requires_explicit_source_target_and_bounded_window() {
        let scope = CaseScope::parse("v1;sources=siem-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z").unwrap();
        assert!(scope.contains(
            "siem-prod",
            Some("123"),
            None,
            "2026-10-23T12:00:00Z",
            "2026-10-23T13:00:00Z"
        ));
        assert!(!scope.contains(
            "siem-other",
            Some("123"),
            None,
            "2026-10-23T12:00:00Z",
            "2026-10-23T13:00:00Z"
        ));
        assert!(!scope.contains(
            "siem-prod",
            Some("456"),
            None,
            "2026-10-23T12:00:00Z",
            "2026-10-23T13:00:00Z"
        ));
        assert!(CaseScope::parse("analyst note").unwrap() == CaseScope::LocalOnly);
        assert!(
            CaseScope::parse(
                "v1;sources=a;accounts=b;hosts=;from=2026-02-30T00:00:00Z;to=2026-03-01T00:00:00Z"
            )
            .is_err()
        );
    }

    #[test]
    fn siem_read_is_allowed_only_inside_explicit_scope() {
        let mut scoped = case();
        scoped.scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        let call = |source: &str| ProposedCall {
            tool: Tool::SiemSearch,
            args: BTreeMap::from([
                ("source".into(), source.into()),
                ("account".into(), "123".into()),
                ("from".into(), "2026-10-23T12:00:00Z".into()),
                ("to".into(), "2026-10-23T13:00:00Z".into()),
                ("query".into(), "AssumeRole".into()),
            ]),
        };
        assert!(matches!(
            evaluate(
                &scoped,
                call("splunk-prod"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        assert!(matches!(
            evaluate(
                &scoped,
                call("splunk-other"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
        assert!(matches!(
            evaluate(
                &case(),
                call("splunk-prod"),
                1,
                ExecutionMode::Attended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
        scoped.scope = "v1;sources=splunk-prod;accounts=;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        assert!(matches!(
            evaluate(
                &scoped,
                call("splunk-prod"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
        scoped.scope = "v1;sources=splunk-prod;accounts=123;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        assert!(matches!(
            evaluate(
                &scoped,
                call("splunk-prod"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    fn cloud_audit_read_requires_account_source_and_window_scope() {
        let mut scoped = case();
        scoped.scope = "v1;sources=aws-prod;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        let call = |account: &str| ProposedCall {
            tool: Tool::CloudAuditEvents,
            args: BTreeMap::from([
                ("source".into(), "aws-prod".into()),
                ("account".into(), account.into()),
                ("from".into(), "2026-10-23T12:00:00Z".into()),
                ("to".into(), "2026-10-23T13:00:00Z".into()),
                ("event_name".into(), "AssumeRole".into()),
            ]),
        };
        assert!(matches!(
            evaluate(
                &scoped,
                call("123456789012"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        assert!(matches!(
            evaluate(
                &scoped,
                call("999999999999"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    fn cloud_identity_read_is_scoped_to_account_and_source() {
        let mut scoped = case();
        scoped.scope = "v1;sources=aws-prod;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        let call = |account: &str| ProposedCall {
            tool: Tool::CloudIdentity,
            args: BTreeMap::from([
                ("source".into(), "aws-prod".into()),
                ("account".into(), account.into()),
                ("kind".into(), "role".into()),
                ("name".into(), "Admin".into()),
            ]),
        };
        assert!(matches!(
            evaluate(
                &scoped,
                call("123456789012"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        assert!(matches!(
            evaluate(
                &scoped,
                call("999999999999"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    fn internal_intel_is_read_only_for_a_scoped_source() {
        let mut scoped = case();
        scoped.scope = "v1;sources=misp-internal;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        let proposal = ProposedCall {
            tool: Tool::ThreatIntelInternal,
            args: BTreeMap::from([
                ("source".into(), "misp-internal".into()),
                ("ioc".into(), "example.com".into()),
            ]),
        };
        assert!(matches!(
            evaluate(
                &scoped,
                proposal.clone(),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        assert!(matches!(
            evaluate(
                &case(),
                proposal,
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    fn unattended_read_is_allowed_but_external_lookup_is_pending() {
        let read = ProposedCall {
            tool: Tool::EvidenceSearch,
            args: BTreeMap::from([("query".into(), "alice".into())]),
        };
        assert!(matches!(
            evaluate(&case(), read, 1, ExecutionMode::Unattended, 1_700_000_000),
            Decision::Allow(_)
        ));
        let external = ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "example.com".into())]),
        };
        assert!(matches!(
            evaluate(
                &case(),
                external,
                2,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    fn graph_queries_are_local_reads_with_bounded_arguments() {
        let args = BTreeMap::from([
            ("kind".into(), "ip".into()),
            ("value".into(), "203.0.113.8".into()),
            ("limit".into(), "20".into()),
        ]);
        assert!(matches!(
            evaluate(
                &case(),
                ProposedCall {
                    tool: Tool::Neighbors,
                    args: args.clone(),
                },
                2,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        let mut invalid = args;
        invalid.insert("limit".into(), "1000".into());
        assert!(matches!(
            evaluate(
                &case(),
                ProposedCall {
                    tool: Tool::Neighbors,
                    args: invalid,
                },
                3,
                ExecutionMode::Attended,
                1_700_000_000
            ),
            Decision::Deny(_)
        ));
        for proposal in [
            ProposedCall {
                tool: Tool::GraphPath,
                args: BTreeMap::from([
                    ("from_kind".into(), "ip".into()),
                    ("from_value".into(), "203.0.113.8".into()),
                    ("to_kind".into(), "user".into()),
                    ("to_value".into(), "alice".into()),
                ]),
            },
            ProposedCall {
                tool: Tool::TextSearch,
                args: BTreeMap::from([
                    ("query".into(), "AssumeRole".into()),
                    ("limit".into(), "20".into()),
                ]),
            },
            ProposedCall {
                tool: Tool::RawRecords,
                args: BTreeMap::from([
                    ("hash".into(), "a".repeat(64)),
                    ("index".into(), "0".into()),
                ]),
            },
        ] {
            assert!(matches!(
                evaluate(
                    &case(),
                    proposal,
                    4,
                    ExecutionMode::Unattended,
                    1_700_000_000
                ),
                Decision::Allow(_)
            ));
        }
        assert!(matches!(
            evaluate(
                &case(),
                ProposedCall {
                    tool: Tool::RawRecords,
                    args: BTreeMap::from([
                        ("hash".into(), "a".repeat(64)),
                        ("index".into(), "100000".into())
                    ]),
                },
                5,
                ExecutionMode::Attended,
                1_700_000_000
            ),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn unattended_edr_reads_require_scoped_host_and_window() {
        let mut scoped = case();
        scoped.scope = "v1;sources=edr-prod;accounts=;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        let info = |host: &str| ProposedCall {
            tool: Tool::EdrHostInfo,
            args: BTreeMap::from([
                ("source".into(), "edr-prod".into()),
                ("host".into(), host.into()),
            ]),
        };
        assert!(matches!(
            evaluate(
                &scoped,
                info("host-1"),
                1,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        assert!(matches!(
            evaluate(
                &scoped,
                info("host-2"),
                2,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
        let detection = |from: &str| ProposedCall {
            tool: Tool::EdrDetections,
            args: BTreeMap::from([
                ("source".into(), "edr-prod".into()),
                ("host".into(), "host-1".into()),
                ("from".into(), from.into()),
                ("to".into(), "2026-10-23T13:00:00Z".into()),
            ]),
        };
        assert!(matches!(
            evaluate(
                &scoped,
                detection("2026-10-23T12:00:00Z"),
                3,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        assert!(matches!(
            evaluate(
                &scoped,
                detection("2026-10-22T12:00:00Z"),
                4,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
        scoped.scope = "v1;sources=edr-prod;accounts=123;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        assert!(matches!(
            evaluate(
                &scoped,
                info("host-1"),
                5,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    fn tainted_external_value_requires_approval() {
        let proposal = Tainted::from_external(
            ProposedCall {
                tool: Tool::ThreatIntelExternal,
                args: BTreeMap::from([("ioc".into(), "example.com".into())]),
            },
            Provenance::new([7; 32], Some(3), SourceKind::ToolResult),
        );
        assert_eq!(proposal.provenance().record_index(), Some(3));
        assert!(matches!(
            evaluate_tainted(
                &case(),
                proposal,
                1,
                ExecutionMode::Attended,
                false,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }

    #[test]
    fn detection_does_not_expand_read_scope() {
        let mut scoped = case();
        scoped.scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
        let proposal = |account: &str| {
            Tainted::from_external(
                ProposedCall {
                    tool: Tool::SiemSearch,
                    args: BTreeMap::from([
                        ("source".into(), "splunk-prod".into()),
                        ("account".into(), account.into()),
                        ("from".into(), "2026-10-23T12:00:00Z".into()),
                        ("to".into(), "2026-10-23T13:00:00Z".into()),
                        ("query".into(), "AssumeRole".into()),
                    ]),
                },
                Provenance::new([8; 32], Some(4), SourceKind::ToolResult),
            )
        };
        assert!(matches!(
            evaluate_tainted(
                &scoped,
                proposal("123"),
                1,
                ExecutionMode::Attended,
                true,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        assert!(matches!(
            evaluate_tainted(
                &scoped,
                proposal("999"),
                2,
                ExecutionMode::Attended,
                true,
                1_700_000_000
            ),
            Decision::NeedsApproval(_)
        ));
    }
}
