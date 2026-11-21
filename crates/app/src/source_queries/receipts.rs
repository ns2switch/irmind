use super::SourceQueryAllocationV1;
use super::{
    CompiledSourceQueryV1, QueryAccounting, QueryPreflightV1, QueryTime, ResolvedQuerySourceV1,
    SourceQueryError, SourceQueryLimits, SourceQueryV1,
    canonical::checked_value,
    canonical_query_json, query_content_id,
    types::{digest, id, text},
};
use irmind_domain::{CaseId, CaseScope, SourceDecoderIdentityV1};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryBudgetV1 {
    version: u64,
    case_id: String,
    revision: u64,
    previous: Option<String>,
    budget: SourceQueryAllocationV1,
    reason: String,
    at: QueryTime,
}

impl SourceQueryBudgetV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        let record: Self = decode_record(bytes)?;
        validate_identity(record.version, &record.case_id, None)?;
        record.budget.validate()?;
        if record.revision == 0
            || (record.revision == 1) != record.previous.is_none()
            || record.previous.as_deref().is_some_and(|hash| !digest(hash))
            || !text(&record.reason, 1024)
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(record)
    }

    pub fn content_id(&self) -> Result<String, SourceQueryError> {
        query_content_id("irmind-source-query-budget-v1", self)
    }
}

pub(crate) struct BudgetReplay<'a> {
    case: &'a str,
    analyst_key: &'a [u8],
    revision: u64,
    previous: Option<String>,
    allocation: SourceQueryAllocationV1,
}

impl<'a> BudgetReplay<'a> {
    pub(crate) fn new(first: &'a crate::SignedEntry, allocation: SourceQueryAllocationV1) -> Self {
        Self {
            case: &first.case_id,
            analyst_key: &first.public_key,
            revision: 0,
            previous: None,
            allocation,
        }
    }

    pub(crate) fn accept(&mut self, entry: &crate::SignedEntry) -> Result<(), crate::AppError> {
        if entry.kind != crate::AuditEventKind::SourceQueryBudgetV1 {
            return Ok(());
        }
        let invalid = || crate::AppError::InvalidChain(entry.seq);
        let record =
            SourceQueryBudgetV1::decode(entry.payload.as_bytes()).map_err(|_| invalid())?;
        if entry.actor != crate::Actor::Analyst
            || entry.public_key != self.analyst_key
            || entry.case_id != self.case
            || record.case_id != self.case
            || entry.evidence.is_some()
            || Some(record.revision) != self.revision.checked_add(1)
            || record.previous != self.previous
        {
            return Err(invalid());
        }
        self.previous = Some(record.content_id().map_err(|_| invalid())?);
        self.revision = record.revision;
        self.allocation = record.budget;
        Ok(())
    }

    pub(crate) const fn current(&self) -> (u64, SourceQueryAllocationV1) {
        (self.revision, self.allocation)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    accounts: Vec<String>,
    projects: Vec<String>,
    workspaces: Vec<String>,
    regions: Vec<String>,
    from: QueryTime,
    to: QueryTime,
    proof: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    sha256: String,
    adoption: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    sha256: String,
    rules: Value,
    adoption: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Decoder {
    pub(super) id: String,
    pub(super) version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Mapping {
    id: String,
    sha256: String,
    target: String,
    version: String,
}

impl Mapping {
    pub(super) fn matches(&self, identity: &irmind_domain::MappingIdentityV1) -> bool {
        self.id == identity.id()
            && self.version == identity.version()
            && self.target == identity.target()
            && self.sha256 == identity.implementation().as_str()
    }

    pub(super) fn validate(&self) -> Result<(), SourceQueryError> {
        if !id(&self.id)
            || !text(&self.version, 128)
            || self.target != "irmind-common-event-v1"
            || !digest(&self.sha256)
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(())
    }
}

/// Canonical plan data. Authentication against case scope and signed organization
/// policy is a separate check before a reservation may grant execution authority.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryPlanV1 {
    version: u64,
    case_id: String,
    task_id: Option<String>,
    pub(super) attempt: u64,
    query: SourceQueryV1,
    compiled: CompiledSourceQueryV1,
    source: ResolvedQuerySourceV1,
    scope: Scope,
    configuration: Configuration,
    policy: Policy,
    allocation_revision: u64,
    preflight: QueryPreflightV1,
    limits: SourceQueryLimits,
    pub(super) decoder: Decoder,
    pub(super) mapping: Mapping,
    at: QueryTime,
}

impl SourceQueryPlanV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        let plan: Self = decode_record(bytes)?;
        plan.validate()?;
        Ok(plan)
    }

    pub fn content_id(&self) -> Result<String, SourceQueryError> {
        query_content_id("irmind-source-query-plan-v1", self)
    }

    pub(super) const fn query(&self) -> &SourceQueryV1 {
        &self.query
    }

    pub(super) const fn compiled(&self) -> &CompiledSourceQueryV1 {
        &self.compiled
    }

    pub(super) fn check_authorized_call(
        &self,
        call: &crate::AuthorizedCall,
    ) -> Result<(), SourceQueryError> {
        if call.tool() != &crate::Tool::SourceQuery
            || call.case_id().as_str() != self.case_id
            || SourceQueryV1::from_proposal(call.proposal_args())? != self.query
        {
            return Err(SourceQueryError::Scope);
        }
        Ok(())
    }

    pub(super) fn adoption(&self) -> &str {
        &self.configuration.adoption
    }

    pub fn validate_scope(
        &self,
        case: &CaseId,
        scope: &CaseScope,
        ceiling: &CaseScope,
    ) -> Result<(), SourceQueryError> {
        if self.case_id != case.as_str()
            || !scope.is_within(ceiling)
            || !self.source.admits(&self.query, scope)
            || !self.source.admits(&self.query, ceiling)
        {
            return Err(SourceQueryError::Scope);
        }
        Ok(())
    }

    pub fn requires_approval(&self, threshold: u64, policy_requires: bool) -> bool {
        let estimate = &self.preflight.estimate;
        policy_requires
            || (self.preflight.accounting == QueryAccounting::ScanPriced
                && (!estimate.reliable || estimate.value.is_none_or(|bytes| bytes > threshold)))
    }

    pub(super) const fn allocation_revision(&self) -> u64 {
        self.allocation_revision
    }

    pub(super) const fn requested_rows(&self) -> u64 {
        self.query.limit()
    }

    pub(super) const fn limits(&self) -> &SourceQueryLimits {
        &self.limits
    }

    pub(super) const fn accounting(&self) -> QueryAccounting {
        self.preflight.accounting
    }

    pub(super) fn analytics_expiry_seconds(&self) -> Option<u64> {
        super::recovery::analytics_lifetime(&self.source, &self.preflight)
    }

    pub(super) fn source(&self) -> &ResolvedQuerySourceV1 {
        &self.source
    }

    pub(super) fn matches_adoption(
        &self,
        hash: &str,
        source: &ResolvedQuerySourceV1,
        policy: &Value,
    ) -> bool {
        self.configuration.adoption == hash
            && self.policy.adoption == hash
            && self.source == *source
            && self.policy.rules == *policy
    }

    fn validate(&self) -> Result<(), SourceQueryError> {
        validate_identity(self.version, &self.case_id, self.task_id.as_deref())?;
        self.limits.validate()?;
        if self.attempt == 0
            || self.query.source() != self.source.id()
            || self.query.dataset() != self.source.dataset()
            || self.query.limit() > self.limits.rows
            || !self.query.interval_within(self.limits.interval_seconds)?
            || self.scope.from.as_str() > self.query.from().as_str()
            || self.scope.to.as_str() < self.query.to().as_str()
            || self.scope.from.as_str() >= self.scope.to.as_str()
        {
            return Err(SourceQueryError::Scope);
        }
        self.validate_scope_snapshot()?;
        self.validate_commitments()?;
        self.validate_preflight()?;
        self.mapping.validate()?;
        SourceDecoderIdentityV1::try_new(&self.decoder.id, &self.decoder.version)
            .map_err(|_| SourceQueryError::Invalid)?;
        Ok(())
    }

    fn validate_scope_snapshot(&self) -> Result<(), SourceQueryError> {
        for values in [
            &self.scope.accounts,
            &self.scope.projects,
            &self.scope.workspaces,
            &self.scope.regions,
        ] {
            if values.len() > 64
                || values.iter().any(|value| !super::native_identifier(value))
                || values.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(SourceQueryError::Scope);
            }
        }
        let permitted_owner = match self.source.module() {
            "query-athena" => self.scope.accounts.as_slice(),
            "query-bigquery" => self.scope.projects.as_slice(),
            _ => self.scope.workspaces.as_slice(),
        };
        if !permitted_owner
            .iter()
            .any(|owner| owner == self.source.owner())
            || !self
                .scope
                .regions
                .iter()
                .any(|region| region == self.source.location())
        {
            return Err(SourceQueryError::Scope);
        }
        Ok(())
    }

    fn validate_commitments(&self) -> Result<(), SourceQueryError> {
        #[derive(Serialize)]
        struct PreflightInput<'a> {
            compiled: &'a CompiledSourceQueryV1,
            source: &'a ResolvedQuerySourceV1,
            scope: &'a Scope,
            limits: &'a SourceQueryLimits,
        }
        let input = PreflightInput {
            compiled: &self.compiled,
            source: &self.source,
            scope: &self.scope,
            limits: &self.limits,
        };
        if !digest(&self.scope.proof)
            || !digest(&self.configuration.adoption)
            || !digest(&self.policy.adoption)
            || !self.policy.rules.is_object()
            || self.configuration.sha256 != fingerprint(&self.source)?
            || self.policy.sha256 != fingerprint(&self.policy.rules)?
            || self.preflight.plan_digest != fingerprint(&input)?
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(())
    }

    fn validate_preflight(&self) -> Result<(), SourceQueryError> {
        let preflight = &self.preflight;
        if preflight.observed_at.as_str() > self.at.as_str()
            || !text(&preflight.estimate.unit, 64)
            || !text(&preflight.estimate.basis, 256)
            || preflight.uncertainty.len() > 32
            || preflight
                .uncertainty
                .iter()
                .any(|reason| !text(reason, 256))
            || !preflight.source_metadata.is_object()
        {
            return Err(SourceQueryError::Invalid);
        }
        match (
            self.source.module(),
            preflight.accounting,
            self.limits.scan_bytes,
        ) {
            ("query-azure-log-analytics", QueryAccounting::AnalyticsNoQueryCharge, None)
                if preflight.provider_ceiling.is_none() && preflight.estimate.value.is_none() =>
            {
                Ok(())
            }
            ("query-athena" | "query-bigquery", QueryAccounting::ScanPriced, Some(limit))
                if preflight.provider_ceiling.is_some_and(|ceiling| {
                    (super::QUERY_MIN_BILLED_BYTES..=limit).contains(&ceiling)
                }) && preflight.estimate.unit == "billed_bytes"
                    && preflight.estimate.value.is_none_or(|bytes| bytes <= limit) =>
            {
                Ok(())
            }
            _ => Err(SourceQueryError::Limit),
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Approve,
    Deny,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryApprovalV1 {
    version: u64,
    case_id: String,
    task_id: Option<String>,
    plan: String,
    decision: Decision,
    reason: String,
    at: QueryTime,
}

impl SourceQueryApprovalV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        let approval: Self = decode_record(bytes)?;
        validate_identity(
            approval.version,
            &approval.case_id,
            approval.task_id.as_deref(),
        )?;
        if !digest(&approval.plan) || !text(&approval.reason, 1024) {
            return Err(SourceQueryError::Invalid);
        }
        Ok(approval)
    }

    pub fn content_id(&self) -> Result<String, SourceQueryError> {
        query_content_id("irmind-source-query-approval-v1", self)
    }

    pub(super) fn plan(&self) -> &str {
        &self.plan
    }

    pub(super) fn case_id(&self) -> &str {
        &self.case_id
    }

    pub(super) fn permits(&self, plan: &SourceQueryPlanV1, id: &str) -> bool {
        self.plan == id
            && self.case_id == plan.case_id
            && self.at.as_str() >= plan.at.as_str()
            && self.decision == Decision::Approve
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryReservationV1 {
    version: u64,
    case_id: String,
    task_id: Option<String>,
    plan: String,
    approval: Option<String>,
    allocation_revision: u64,
    scan_bytes: Option<u64>,
    retained_rows: u64,
    retained_bytes: u64,
    at: QueryTime,
}

impl SourceQueryReservationV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        let reservation: Self = decode_record(bytes)?;
        validate_identity(
            reservation.version,
            &reservation.case_id,
            reservation.task_id.as_deref(),
        )?;
        if !digest(&reservation.plan)
            || reservation
                .approval
                .as_deref()
                .is_some_and(|hash| !digest(hash))
            || reservation.scan_bytes == Some(0)
            || !(1..=super::QUERY_MAX_ROWS).contains(&reservation.retained_rows)
            || !(1..=super::QUERY_MAX_BYTES).contains(&reservation.retained_bytes)
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(reservation)
    }

    pub fn content_id(&self) -> Result<String, SourceQueryError> {
        query_content_id("irmind-source-query-reservation-v1", self)
    }

    pub(super) fn plan(&self) -> &str {
        &self.plan
    }

    pub(super) fn approval(&self) -> Option<&str> {
        self.approval.as_deref()
    }

    pub(super) fn check(
        &self,
        plan: &SourceQueryPlanV1,
        approval: Option<&str>,
    ) -> Result<(), SourceQueryError> {
        if self.plan != plan.content_id()?
            || self.case_id != plan.case_id
            || self.at.as_str() < plan.at.as_str()
            || self.approval.as_deref() != approval
            || self.allocation_revision != plan.allocation_revision
            || self.scan_bytes != plan.limits.scan_bytes
            || self.retained_rows != plan.limits.rows
            || self.retained_bytes != plan.limits.retained_bytes
        {
            return Err(SourceQueryError::Approval);
        }
        Ok(())
    }
}

pub(super) fn validate_identity(
    version: u64,
    case: &str,
    task: Option<&str>,
) -> Result<(), SourceQueryError> {
    if task.is_some() {
        return Err(SourceQueryError::Subagent);
    }
    let case_id = uuid::Uuid::parse_str(case).map_err(|_| SourceQueryError::Invalid)?;
    if version != 1 || case_id.to_string() != case {
        return Err(SourceQueryError::Invalid);
    }
    Ok(())
}

pub(super) fn decode_record<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, SourceQueryError> {
    let record =
        serde_json::from_value(checked_value(bytes)?).map_err(|_| SourceQueryError::Invalid)?;
    if canonical_query_json(&record)? != bytes {
        return Err(SourceQueryError::Invalid);
    }
    Ok(record)
}

fn fingerprint<T: Serialize>(value: &T) -> Result<String, SourceQueryError> {
    Ok(crate::hex(&crate::sha256(&canonical_query_json(value)?)))
}
