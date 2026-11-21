use super::{
    QueryAccounting, QueryPreflightV1, QueryTime, ResolvedQuerySourceV1, SourceQueryError,
    SourceQueryExecutionV1, SourceQueryHold, query_content_id,
    receipts::{decode_record, validate_identity},
    types::{digest, text},
};
use crate::{AppError, AuditEventKind, AuditOrigin, CancellationToken, CaseId, Engine};
use serde::{Deserialize, Serialize};

// Azure documents separate maxima for the Analytics concurrency queue and
// the running query. Compute expiry from the observed unknown outcome.
const AZURE_ANALYTICS_LIFETIME_SECONDS: u64 = 3 * 60 + 10 * 60;

pub(super) fn analytics_lifetime(
    source: &ResolvedQuerySourceV1,
    preflight: &QueryPreflightV1,
) -> Option<u64> {
    if source.module() != "query-azure-log-analytics"
        || source.module_version() != "1"
        || !matches!(
            source.table(),
            "SigninLogs" | "AADNonInteractiveUserSignInLogs" | "AuditLogs" | "AzureActivity"
        )
        || preflight.accounting != QueryAccounting::AnalyticsNoQueryCharge
        || preflight
            .source_metadata
            .get("plan")
            .and_then(serde_json::Value::as_str)
            != Some("Analytics")
        || preflight
            .source_metadata
            .get("provisioning_state")
            .and_then(serde_json::Value::as_str)
            != Some("Succeeded")
    {
        return None;
    }
    Some(AZURE_ANALYTICS_LIFETIME_SECONDS)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryAction {
    AcknowledgeExpiredAnalytics,
}

/// Acknowledges uncertainty after documented expiry. The accounting hold and
/// observation stay in custody and only the execution slot becomes available.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryRecoveryV1 {
    version: u64,
    case_id: String,
    plan: String,
    reservation: String,
    execution: String,
    action: RecoveryAction,
    reason: String,
    not_before: QueryTime,
    at: QueryTime,
}

impl SourceQueryRecoveryV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        let record: Self = decode_record(bytes)?;
        validate_identity(record.version, &record.case_id, None)?;
        if ![&record.plan, &record.reservation, &record.execution]
            .into_iter()
            .all(|value| digest(value))
            || !text(&record.reason, 1024)
            || record.at.as_str() < record.not_before.as_str()
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(record)
    }

    pub fn content_id(&self) -> Result<String, SourceQueryError> {
        query_content_id("irmind-source-query-recovery-v1", self)
    }

    pub fn reservation(&self) -> &str {
        &self.reservation
    }

    pub(super) fn validate_observation(
        &self,
        case: &CaseId,
        hold: &SourceQueryHold,
        execution: &SourceQueryExecutionV1,
        observation_signed_time: u64,
        signed_time: u64,
    ) -> Result<(), SourceQueryError> {
        if self.case_id != case.as_str()
            || self.plan != hold.plan
            || self.reservation != hold.id()
            || self.execution != execution.content_id()?
            || hold.accounting != QueryAccounting::AnalyticsNoQueryCharge
            || hold.resources().scan_bytes != 0
        {
            return Err(SourceQueryError::Unresolved);
        }
        let lifetime = hold
            .analytics_expiry_seconds
            .ok_or(SourceQueryError::Unresolved)?;
        let observed = execution
            .unknown_analytics_observed_at()?
            .nanos()?
            .max(i128::from(observation_signed_time) * 1_000_000_000);
        let earliest = observed + i128::from(lifetime) * 1_000_000_000;
        if self.not_before.nanos()? < earliest
            || i128::from(signed_time) * 1_000_000_000 < self.at.nanos()?
        {
            return Err(SourceQueryError::Unresolved);
        }
        Ok(())
    }
}

impl Engine<'_> {
    pub fn acknowledge_expired_analytics_query(
        &self,
        case: &CaseId,
        payload: &str,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("acknowledge an expired Analytics query")?;
        SourceQueryRecoveryV1::decode(payload.as_bytes())?;
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        if self.repo.get_case(case)?.sealed {
            return Err(AppError::Sealed);
        }
        let mut entries = self.audit_log.entries(case)?;
        let entry = self.signed_entry_after(
            case,
            entries.last(),
            AuditOrigin::Analyst,
            AuditEventKind::SourceQueryRecoveryV1,
            payload,
            None,
        )?;
        entries.push(entry);
        self.verify_source_query_journal(&entries, cancel, false)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.audit_log
            .append(entries.last().ok_or(AppError::InvalidChain(0))?)
    }
}
