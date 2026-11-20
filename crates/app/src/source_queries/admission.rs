use super::{
    QUERY_MAX_RECORD_BYTES, ResolvedQuerySourceV1, SourceQueryApprovalV1, SourceQueryBroker,
    SourceQueryError, SourceQueryHold, SourceQueryPlanV1, SourceQueryReservationV1,
    canonical::checked_value, canonical_query_json,
};
use crate::{
    Actor, AppError, AuditEventKind, CaseId, CaseScope, SignedEntry, SignedOperation, Verifier,
};
use irmind_domain::AgentId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const CONFIGURATION_PREFIX: &str = "source-query-configuration-v1:";

#[derive(Clone, Copy)]
pub struct SignedSourceQueryAdmission<'a> {
    pub plan: &'a SignedEntry,
    pub approval: Option<&'a SignedEntry>,
    pub reservation: &'a SignedEntry,
    pub configuration: &'a SignedOperation,
}

#[derive(Clone, Copy)]
pub struct SourceQueryAuthority<'a> {
    pub principal: &'a AgentId,
    pub case_scope: &'a CaseScope,
    pub organization_scope: &'a CaseScope,
    pub requires_policy_approval: bool,
    pub verifier: &'a dyn Verifier,
}

impl SourceQueryBroker {
    /// Apply authenticated admission receipts to a reconstructed accounting
    /// state. The caller supplies the verified case chain under the case lock.
    pub fn reserve_authenticated(
        &mut self,
        records: SignedSourceQueryAdmission<'_>,
        authority: SourceQueryAuthority<'_>,
    ) -> Result<SourceQueryHold, AppError> {
        let principal = Actor::Agent(authority.principal.clone());
        let verifier = authority.verifier;
        verify_entry(
            records.plan,
            self.case(),
            AuditEventKind::SourceQueryPlanV1,
            &principal,
            verifier,
        )?;
        verify_entry(
            records.reservation,
            self.case(),
            AuditEventKind::SourceQueryReservationV1,
            &principal,
            verifier,
        )?;
        if records.plan.seq >= records.reservation.seq {
            return Err(SourceQueryError::Approval.into());
        }
        let plan = SourceQueryPlanV1::decode(records.plan.payload.as_bytes())?;
        let reservation = SourceQueryReservationV1::decode(records.reservation.payload.as_bytes())?;
        let approval = records
            .approval
            .map(|entry| {
                verify_entry(
                    entry,
                    self.case(),
                    AuditEventKind::SourceQueryApprovalV1,
                    &Actor::Analyst,
                    verifier,
                )?;
                if entry.seq <= records.plan.seq || entry.seq >= records.reservation.seq {
                    return Err(SourceQueryError::Approval.into());
                }
                Ok::<_, AppError>(SourceQueryApprovalV1::decode(entry.payload.as_bytes())?)
            })
            .transpose()?;
        let scan_threshold = adopted_threshold(&plan, records.configuration, verifier)?;
        Ok(self.reserve(
            &plan,
            &reservation,
            approval.as_ref(),
            authority.case_scope,
            authority.organization_scope,
            scan_threshold,
            authority.requires_policy_approval,
            records.reservation.seq,
        )?)
    }
}

pub(super) fn verify_entry(
    entry: &SignedEntry,
    case: &CaseId,
    kind: AuditEventKind,
    actor: &Actor,
    verifier: &dyn Verifier,
) -> Result<(), AppError> {
    let invalid = || AppError::InvalidChain(entry.seq);
    if entry.seq == 0
        || entry.case_id != case.as_str()
        || entry.kind != kind
        || entry.actor != *actor
        || entry.evidence.is_some()
        || entry.payload.len() > QUERY_MAX_RECORD_BYTES
        || entry.public_key != verifier.trusted_public_key(actor)?
        || crate::sha256(&entry.canonical()) != entry.hash
    {
        return Err(invalid());
    }
    verifier
        .verify(&entry.public_key, &entry.hash, &entry.sig)
        .map_err(|_| invalid())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Adoption {
    version: u64,
    source: ResolvedQuerySourceV1,
    policy: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRules {
    #[serde(default)]
    accounts: Vec<String>,
    #[serde(default)]
    projects: Vec<String>,
    #[serde(default)]
    workspaces: Vec<String>,
    regions: Vec<String>,
    sources: Vec<String>,
    interval_seconds: u64,
    query_retained_bytes: u64,
    query_rows: u64,
    query_scan_bytes: Option<u64>,
    scan_approval_threshold: Option<u64>,
}

fn adopted_threshold(
    plan: &SourceQueryPlanV1,
    operation: &SignedOperation,
    verifier: &dyn Verifier,
) -> Result<u64, AppError> {
    let invalid = || AppError::from(SourceQueryError::Approval);
    let encoded = operation
        .operation
        .strip_prefix(CONFIGURATION_PREFIX)
        .ok_or_else(invalid)?;
    if operation.case_id != crate::GLOBAL_OPERATION_SCOPE
        || operation.seq == 0
        || operation.actor != Actor::Analyst
        || encoded.len() > QUERY_MAX_RECORD_BYTES * 2
        || operation.public_key != verifier.trusted_public_key(&Actor::Analyst)?
        || crate::sha256(&operation.canonical()) != operation.hash
    {
        return Err(invalid());
    }
    verifier
        .verify(&operation.public_key, &operation.hash, &operation.sig)
        .map_err(|_| invalid())?;
    let bytes = hex::decode(encoded).map_err(|_| invalid())?;
    let adoption: Adoption =
        serde_json::from_value(checked_value(&bytes)?).map_err(|_| invalid())?;
    if adoption.version != 1
        || crate::hex(&bytes) != encoded
        || canonical_query_json(&adoption)? != bytes
        || !plan.matches_adoption(
            &crate::hex(&operation.hash),
            &adoption.source,
            &adoption.policy,
        )
    {
        return Err(invalid());
    }
    let rules: PolicyRules = serde_json::from_value(adoption.policy).map_err(|_| invalid())?;
    let source = plan.source();
    let owners = match source.module() {
        "query-athena" => rules.accounts,
        "query-bigquery" => rules.projects,
        _ => rules.workspaces,
    };
    let limits = plan.limits();
    if !owners.iter().any(|owner| owner == source.owner())
        || !rules
            .regions
            .iter()
            .any(|region| region == source.location())
        || !rules.sources.iter().any(|allowed| allowed == source.id())
        || limits.interval_seconds > rules.interval_seconds
        || limits.rows > rules.query_rows
        || limits.retained_bytes > rules.query_retained_bytes
        || limits
            .scan_bytes
            .is_some_and(|scan| rules.query_scan_bytes.is_none_or(|cap| scan > cap))
    {
        return Err(SourceQueryError::Scope.into());
    }
    Ok(rules.scan_approval_threshold.unwrap_or(0))
}
