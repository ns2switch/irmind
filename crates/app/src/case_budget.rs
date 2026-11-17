//! Analyst allocations are distinct from the organization's immutable ceiling.
use crate::{AppError, PolicyRules, SignedEntry, UsageEvent};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseBudgetLimits {
    pub model_tokens: u64,
    pub tool_calls: u64,
    pub cloud_bytes: u64,
}
impl Default for CaseBudgetLimits {
    fn default() -> Self {
        Self::from_policy(&PolicyRules::default())
    }
}
impl CaseBudgetLimits {
    pub fn validate(self) -> Result<(), AppError> {
        let policy = PolicyRules {
            max_model_tokens_per_case: self.model_tokens,
            max_tool_calls_per_case: usize::try_from(self.tool_calls).unwrap_or(usize::MAX),
            max_object_bytes_per_case: self.cloud_bytes,
            max_object_read_bytes: 1,
            object_transfer_approval_bytes: 1,
            ..PolicyRules::default()
        };
        policy
            .validate()
            .map_err(|_| AppError::Policy("case limits exceed the fixed supported bounds".into()))
    }
    pub fn from_policy(policy: &PolicyRules) -> Self {
        Self {
            model_tokens: policy.max_model_tokens_per_case,
            tool_calls: policy.max_tool_calls_per_case as u64,
            cloud_bytes: policy.max_object_bytes_per_case,
        }
    }
    #[must_use]
    pub fn intersection(self, other: Self) -> Self {
        Self {
            model_tokens: self.model_tokens.min(other.model_tokens),
            tool_calls: self.tool_calls.min(other.tool_calls),
            cloud_bytes: self.cloud_bytes.min(other.cloud_bytes),
        }
    }
    pub fn within(self, ceiling: Self) -> bool {
        self.intersection(ceiling) == self
    }
    pub fn increases(self, previous: Self) -> bool {
        self.model_tokens > previous.model_tokens
            || self.tool_calls > previous.tool_calls
            || self.cloud_bytes > previous.cloud_bytes
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaseBudgetUsage {
    pub model_tokens: u64,
    pub tool_calls: u64,
    /// Reserved transfer bytes, including unsuccessful reads, as in enforcement.
    pub cloud_bytes: u64,
    pub cost_microusd: Option<u64>,
    pub provider_usage_available: bool,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub ordinary_input_tokens: u64,
    pub reported_cache: Option<crate::CacheUsage>,
    pub cache_reporting_complete: bool,
}
impl CaseBudgetUsage {
    pub fn fits(self, limits: CaseBudgetLimits) -> bool {
        self.model_tokens <= limits.model_tokens
            && self.tool_calls <= limits.tool_calls
            && self.cloud_bytes <= limits.cloud_bytes
    }
}
#[derive(Clone, Copy, Debug)]
pub struct CaseBudgetStatus {
    pub allocated: Option<CaseBudgetLimits>,
    pub organization: CaseBudgetLimits,
    pub effective: Option<CaseBudgetLimits>,
    pub usage: CaseBudgetUsage,
}
impl CaseBudgetStatus {
    pub fn require_effective(self) -> Result<CaseBudgetLimits, AppError> {
        self.effective.ok_or_else(|| {
            AppError::Policy(
                "approve this case's limits with /budget before starting model or tool work".into(),
            )
        })
    }

    pub fn notice(self, reason: &str) -> String {
        let Some(effective) = self.effective else {
            return "No signed case allocation. Review and confirm limits with /budget; the organization ceiling applies.".into();
        };
        format!(
            "Limit reached ({reason}). Recorded tokens {}/{}, calls {}/{}, reserved cloud bytes {}/{}. Use /budget to review the allocation; the organization ceiling still applies.",
            self.usage.model_tokens,
            effective.model_tokens,
            self.usage.tool_calls,
            effective.tool_calls,
            self.usage.cloud_bytes,
            effective.cloud_bytes
        )
    }
    pub fn warning(self) -> bool {
        let Some(effective) = self.effective else {
            return false;
        };
        [
            (self.usage.model_tokens, effective.model_tokens),
            (self.usage.tool_calls, effective.tool_calls),
            (self.usage.cloud_bytes, effective.cloud_bytes),
        ]
        .iter()
        .any(|(used, limit)| u128::from(*used) * 100 >= u128::from(*limit) * 80)
    }
}

pub fn case_budget_usage(entries: &[SignedEntry]) -> Result<CaseBudgetUsage, AppError> {
    let mut ledger = UsageAccumulator::default();
    for entry in entries {
        ledger.push(entry)?;
    }
    Ok(ledger.finish())
}

pub(crate) struct UsageAccumulator {
    usage: CaseBudgetUsage,
    models: std::collections::BTreeMap<String, ActorModelUsage>,
    cost_complete: bool,
    cache_complete: bool,
}
#[derive(Default)]
struct ActorModelUsage {
    requests: u64,
    replies: u64,
    reports: u64,
}
impl Default for UsageAccumulator {
    fn default() -> Self {
        Self {
            usage: CaseBudgetUsage::default(),
            models: std::collections::BTreeMap::new(),
            cost_complete: true,
            cache_complete: true,
        }
    }
}
impl UsageAccumulator {
    pub(crate) fn push(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        match entry.kind {
            crate::AuditEventKind::SubagentReservationV1 => {
                use crate::subagents::{
                    ReservationAction, ReservationPurpose, SubagentRecord, SubagentReservationV1,
                };
                let (_, encoded) = entry.payload.split_once(':').ok_or_else(invalid)?;
                if encoded.len() > 512 * 1024 {
                    return Err(invalid());
                }
                let bytes = hex::decode(encoded).map_err(|_| invalid())?;
                let reservation = SubagentReservationV1::decode(&bytes).map_err(|_| invalid())?;
                if reservation.action == ReservationAction::ReserveRequest
                    && reservation.purpose == ReservationPurpose::Model
                    && reservation.task_id.is_some()
                {
                    let model = self.models.entry(entry.actor.as_storage()).or_default();
                    model.requests = model.requests.checked_add(1).ok_or_else(invalid)?;
                }
            }
            crate::AuditEventKind::ModelRequest => {
                let model = self.models.entry(entry.actor.as_storage()).or_default();
                model.requests = model.requests.checked_add(1).ok_or_else(invalid)?;
            }
            crate::AuditEventKind::ModelReply => {
                let model = self.models.entry(entry.actor.as_storage()).or_default();
                model.replies = model.replies.checked_add(1).ok_or_else(invalid)?;
            }
            crate::AuditEventKind::ModelUsage => {
                self.add_model_usage(entry)?;
            }
            crate::AuditEventKind::Allowed | crate::AuditEventKind::ToolDispatch => {
                self.usage.tool_calls = self.usage.tool_calls.checked_add(1).ok_or_else(invalid)?;
                if let Ok(reservation) = serde_json::from_str::<Reservation>(&entry.payload)
                    && reservation.version == 1
                    && reservation.tool == "object_read"
                {
                    self.usage.cloud_bytes = self
                        .usage
                        .cloud_bytes
                        .checked_add(reservation.reserved_bytes)
                        .ok_or_else(invalid)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn add_model_usage(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        let event: UsageEvent = serde_json::from_str(&entry.payload).map_err(|_| invalid())?;
        let model = self.models.entry(entry.actor.as_storage()).or_default();
        model.reports = model.reports.checked_add(1).ok_or_else(invalid)?;
        self.usage.model_tokens = self
            .usage
            .model_tokens
            .checked_add(event.input_tokens)
            .and_then(|n| n.checked_add(event.output_tokens))
            .ok_or_else(invalid)?;
        self.usage.input_tokens = self
            .usage
            .input_tokens
            .checked_add(event.input_tokens)
            .ok_or_else(invalid)?;
        self.usage.output_tokens = self
            .usage
            .output_tokens
            .checked_add(event.output_tokens)
            .ok_or_else(invalid)?;
        if let Some(cache) = event.cache {
            self.usage.ordinary_input_tokens = self
                .usage
                .ordinary_input_tokens
                .checked_add(cache.ordinary_input_tokens(event.input_tokens)?)
                .ok_or_else(invalid)?;
            self.usage.reported_cache = Some(match self.usage.reported_cache {
                Some(previous) => previous.checked_add(cache)?,
                None => cache,
            });
        } else {
            self.cache_complete = false;
        }
        if let Some(cost) = event.estimated_cost_microusd {
            self.usage.cost_microusd = Some(
                self.usage
                    .cost_microusd
                    .unwrap_or(0)
                    .checked_add(cost)
                    .ok_or_else(invalid)?,
            );
        } else {
            self.cost_complete = false;
        }
        Ok(())
    }
    pub(crate) fn finish(&self) -> CaseBudgetUsage {
        let mut usage = self.usage;
        usage.provider_usage_available = self
            .models
            .values()
            .all(|model| model.reports >= model.replies.max(model.requests));
        usage.cache_reporting_complete =
            self.cache_complete && usage.provider_usage_available && usage.reported_cache.is_some();
        if !self.cost_complete || !usage.provider_usage_available {
            usage.cost_microusd = None;
        }
        usage
    }
}
#[derive(Deserialize)]
struct Reservation {
    version: u8,
    tool: String,
    reserved_bytes: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::AuditEventKind;
    fn entry(kind: AuditEventKind, payload: &str) -> SignedEntry {
        SignedEntry {
            seq: 1,
            case_id: "synthetic".into(),
            at: 0,
            actor: irmind_domain::Actor::Analyst,
            origin: "System".into(),
            kind,
            payload: payload.into(),
            evidence: None,
            prev: [0; 32],
            hash: [0; 32],
            sig: vec![],
            public_key: vec![],
        }
    }
    #[test]
    fn cache_is_charged_in_full_and_unknown_reports_do_not_become_zero() {
        let entries = [
            entry(
                AuditEventKind::ModelUsage,
                r#"{"input_tokens":1000,"output_tokens":50,"estimated_cost_microusd":380,"cache":{"read_input_tokens":800,"write_input_tokens":0,"write_lifetime":"not-applicable"}}"#,
            ),
            entry(
                AuditEventKind::ModelUsage,
                r#"{"input_tokens":500,"output_tokens":20,"estimated_cost_microusd":null}"#,
            ),
        ];
        let complete = case_budget_usage(&entries[..1]).unwrap();
        assert_eq!(complete.model_tokens, 1050);
        assert_eq!(complete.ordinary_input_tokens, 200);
        assert!(complete.cache_reporting_complete);
        let partial = case_budget_usage(&entries).unwrap();
        assert_eq!(partial.model_tokens, 1570);
        assert_eq!(partial.reported_cache.unwrap().read_input_tokens(), 800);
        assert!(!partial.cache_reporting_complete);
        assert_eq!(partial.cost_microusd, None);
        assert_eq!(
            crate::summarize_usage(&entries)
                .unwrap()
                .estimated_cost_microusd,
            None
        );
        assert_eq!(
            crate::summarize_usage(&[entries[1].clone(), entries[0].clone()])
                .unwrap()
                .estimated_cost_microusd,
            None
        );
    }
    #[test]
    fn case_budget_accounts_reserved_cloud_bytes_and_reports_missing_usage_honestly() {
        let entries = [
            entry(AuditEventKind::ModelRequest, "request"),
            entry(AuditEventKind::ModelReply, "reply"),
            entry(
                AuditEventKind::ModelUsage,
                r#"{"input_tokens":8,"output_tokens":2,"estimated_cost_microusd":20}"#,
            ),
            entry(
                AuditEventKind::ToolDispatch,
                r#"{"version":1,"tool":"object_read","args":{},"reserved_bytes":1024}"#,
            ),
        ];
        let usage = case_budget_usage(&entries).unwrap();
        assert_eq!(usage.model_tokens, 10);
        assert_eq!(usage.tool_calls, 1);
        assert_eq!(usage.cloud_bytes, 1024);
        assert_eq!(usage.cost_microusd, Some(20));
        assert!(usage.provider_usage_available);
        let mut interrupted = entries.to_vec();
        interrupted.push(entry(AuditEventKind::ModelRequest, "another request"));
        interrupted.push(entry(AuditEventKind::Cancelled, "cancelled"));
        let missing = case_budget_usage(&interrupted).unwrap();
        assert!(!missing.provider_usage_available);
        assert_eq!(missing.model_tokens, 10);
        assert_eq!(missing.cost_microusd, None);
    }
    #[test]
    fn case_budget_validates_fixed_bounds_and_warns_at_exactly_eighty_percent() {
        let limits = CaseBudgetLimits::default();
        assert!(limits.validate().is_ok());
        assert!(
            CaseBudgetLimits {
                model_tokens: 10_000_001,
                ..limits
            }
            .validate()
            .is_err()
        );
        assert!(
            CaseBudgetLimits {
                tool_calls: 10_001,
                ..limits
            }
            .validate()
            .is_err()
        );
        assert!(
            CaseBudgetLimits {
                cloud_bytes: 10_995_116_277_761,
                ..limits
            }
            .validate()
            .is_err()
        );
        let mut status = CaseBudgetStatus {
            allocated: Some(limits),
            organization: limits,
            effective: Some(limits),
            usage: CaseBudgetUsage::default(),
        };
        status.usage.tool_calls = 799;
        assert!(!status.warning());
        status.usage.tool_calls = 800;
        assert!(status.warning());
        let tighter = CaseBudgetLimits {
            model_tokens: 100,
            ..limits
        };
        assert_eq!(limits.intersection(tighter), tighter);
        assert!(!limits.within(tighter));
    }

    #[test]
    fn child_token_charges_never_mask_missing_parent_provider_usage() {
        use crate::subagents::{
            ReservationAction, ReservationPurpose, ReservationTransition, SubagentDigest,
            SubagentPlanV1, SubagentRecord, SubagentReservationV1, SubagentResources,
        };
        let mut child = entry(
            AuditEventKind::ModelUsage,
            r#"{"input_tokens":12,"output_tokens":8,"estimated_cost_microusd":30}"#,
        );
        child.actor =
            irmind_domain::Actor::Agent(irmind_domain::AgentId::parse("skills-agent").unwrap());
        let plan = SubagentPlanV1::decode(include_bytes!(
            "../../../docs/development/subagent-format-vectors/plan.json"
        ))
        .unwrap();
        let request = SubagentReservationV1::prepare(
            &plan,
            Some(plan.tasks[0].task_id),
            1,
            ReservationAction::ReserveRequest,
            ReservationPurpose::Model,
            ReservationTransition {
                amount: SubagentResources {
                    tokens: 100,
                    rounds: 1,
                    calls: 0,
                    cloud_bytes: 0,
                },
                parent_operation: Some(SubagentDigest::from_bytes([1; 32])),
                cause_sha256: SubagentDigest::from_bytes([2; 32]),
                accounting_audit_sha256: None,
            },
        )
        .unwrap();
        let mut reserved = entry(
            AuditEventKind::SubagentReservationV1,
            &request.audit_payload().unwrap(),
        );
        reserved.actor = child.actor.clone();
        let no_report = case_budget_usage(std::slice::from_ref(&reserved)).unwrap();
        assert!(!no_report.provider_usage_available);
        assert_eq!(no_report.cost_microusd, None);
        let mut entries = vec![
            entry(AuditEventKind::ModelRequest, "parent"),
            reserved,
            child,
        ];
        let unknown = case_budget_usage(&entries).unwrap();
        assert_eq!(unknown.model_tokens, 20);
        assert!(!unknown.provider_usage_available);
        assert_eq!(unknown.cost_microusd, None);
        entries.push(entry(
            AuditEventKind::ModelUsage,
            r#"{"input_tokens":2,"output_tokens":3,"estimated_cost_microusd":10}"#,
        ));
        let known = case_budget_usage(&entries).unwrap();
        assert_eq!(known.model_tokens, 25);
        assert!(known.provider_usage_available);
        assert_eq!(known.cost_microusd, Some(40));
        let mut request = entry(AuditEventKind::ModelRequest, "unattended root");
        request.actor =
            irmind_domain::Actor::Agent(irmind_domain::AgentId::parse("automation").unwrap());
        entries.push(request.clone());
        assert!(
            !case_budget_usage(&entries)
                .unwrap()
                .provider_usage_available
        );
        let mut report = entry(
            AuditEventKind::ModelUsage,
            r#"{"input_tokens":1,"output_tokens":1,"estimated_cost_microusd":1}"#,
        );
        report.actor = request.actor;
        entries.push(report);
        assert!(
            case_budget_usage(&entries)
                .unwrap()
                .provider_usage_available
        );
    }
}
