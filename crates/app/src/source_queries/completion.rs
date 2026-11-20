use super::{
    QUERY_MAX_BYTES, QUERY_MAX_PAGES, QUERY_MAX_ROWS, QueryAccounting, QueryCaptureSummary,
    QueryTime, SourceQueryBroker, SourceQueryError, SourceQueryHold, SourceQueryUsage,
    admission::verify_entry,
    query_content_id,
    receipts::{Decoder, Mapping, decode_record, validate_identity},
    types::{digest, text},
};
use crate::{Actor, AppError, AuditEventKind, SignedEntry, Verifier};
use irmind_domain::{AgentId, SourceDecoderIdentityV1};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Intent,
    Accepted,
    Running,
    Terminal,
}

#[derive(Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pending,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
    Unknown,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryExecutionV1 {
    version: u64,
    case_id: String,
    plan: String,
    reservation: String,
    previous: Option<String>,
    attempt: u64,
    phase: Phase,
    execution_key: String,
    provider_id: Option<String>,
    provider_request_id: Option<String>,
    started_at: QueryTime,
    observed_at: QueryTime,
    provider_at: Option<QueryTime>,
    status: Status,
    usage: SourceQueryUsage,
    source_observation: Option<Value>,
    reason: Option<String>,
}

impl SourceQueryExecutionV1 {
    pub(super) fn unknown_analytics_observed_at(&self) -> Result<&QueryTime, SourceQueryError> {
        if self.phase != Phase::Terminal
            || self.status != Status::Unknown
            || self.provider_id.is_some()
            || self.usage.query_price_basis != QueryAccounting::AnalyticsNoQueryCharge
            || self.usage.scanned_bytes.is_some()
            || self.usage.processed_bytes.is_some()
            || self.usage.billed_bytes.is_some()
        {
            return Err(SourceQueryError::Unresolved);
        }
        Ok(&self.observed_at)
    }
    pub(super) fn reservation(&self) -> &str {
        &self.reservation
    }

    pub(super) fn check_submit_intent(
        &self,
        plan: &super::SourceQueryPlanV1,
        reservation: &super::SourceQueryReservationV1,
        reservation_frame: &SignedEntry,
        intent_frame: &SignedEntry,
    ) -> Result<(), SourceQueryError> {
        if self.phase != Phase::Intent
            || self.case_id != reservation_frame.case_id
            || self.plan != plan.content_id()?
            || self.reservation != reservation.content_id()?
            || self.attempt != plan.attempt
            || self.usage.query_price_basis != plan.accounting()
            || Some(intent_frame.seq) != reservation_frame.seq.checked_add(1)
            || intent_frame.prev != reservation_frame.hash
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        let record: Self = decode_record(bytes)?;
        validate_identity(record.version, &record.case_id, None)?;
        validate_links(&[&record.plan, &record.reservation, &record.execution_key])?;
        if record.attempt == 0
            || record.started_at.as_str() > record.observed_at.as_str()
            || record
                .previous
                .as_deref()
                .is_some_and(|value| !digest(value))
            || record
                .provider_id
                .as_deref()
                .is_some_and(|value| !text(value, 1024))
            || record
                .provider_request_id
                .as_deref()
                .is_some_and(|value| !text(value, 1024))
            || record
                .reason
                .as_deref()
                .is_some_and(|value| !text(value, 1024))
            || record
                .source_observation
                .as_ref()
                .is_some_and(|value| !value.is_object())
        {
            return Err(SourceQueryError::Invalid);
        }
        let intent = record.phase == Phase::Intent;
        if intent == record.previous.is_some()
            || (intent
                && (record.provider_id.is_some()
                    || record.provider_request_id.is_some()
                    || record.usage.returned_wire_bytes != 0
                    || record.usage.returned_decoded_bytes != 0
                    || record.usage.scanned_bytes.is_some()
                    || record.usage.processed_bytes.is_some()
                    || record.usage.billed_bytes.is_some()))
            || ((record.phase == Phase::Terminal) == (record.status == Status::Pending))
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(record)
    }

    pub fn content_id(&self) -> Result<String, SourceQueryError> {
        query_content_id("irmind-source-query-execution-v1", self)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryResultV1 {
    version: u64,
    case_id: String,
    plan: String,
    reservation: String,
    execution: String,
    capture_sha256: String,
    capture_bytes: u64,
    page_count: u64,
    page_commitment: String,
    row_count: u64,
    rejected_rows: u64,
    completeness: Vec<String>,
    coverage: Vec<String>,
    decoder: Decoder,
    mapping: Mapping,
    at: QueryTime,
}

impl SourceQueryResultV1 {
    pub(super) fn reservation(&self) -> &str {
        &self.reservation
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        let record: Self = decode_record(bytes)?;
        validate_identity(record.version, &record.case_id, None)?;
        validate_links(&[
            &record.plan,
            &record.reservation,
            &record.execution,
            &record.capture_sha256,
            &record.page_commitment,
        ])?;
        if !(1..=QUERY_MAX_BYTES).contains(&record.capture_bytes)
            || record.page_count > QUERY_MAX_PAGES
            || record
                .row_count
                .checked_add(record.rejected_rows)
                .is_none_or(|rows| rows > QUERY_MAX_ROWS)
            || !bounded_reasons(&record.completeness)
            || record
                .completeness
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !bounded_reasons(&record.coverage)
            || record.completeness.iter().any(|value| {
                !matches!(
                    value.as_str(),
                    "provider_partial" | "local_limit" | "cancelled" | "rejected"
                )
            })
        {
            return Err(SourceQueryError::Invalid);
        }
        SourceDecoderIdentityV1::try_new(&record.decoder.id, &record.decoder.version)
            .map_err(|_| SourceQueryError::Invalid)?;
        record.mapping.validate()?;
        Ok(record)
    }

    pub fn content_id(&self) -> Result<String, SourceQueryError> {
        query_content_id("irmind-source-query-result-v1", self)
    }

    pub fn capture_identity(&self) -> (&str, u64) {
        (&self.capture_sha256, self.capture_bytes)
    }

    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    pub fn capture_path(&self) -> String {
        format!("queries/{}.sqc", self.capture_sha256)
    }

    pub fn matches_decoder(&self, identity: crate::ParserIdentity<'_>) -> bool {
        self.decoder.id == identity.name && self.decoder.version == identity.version
    }

    pub fn matches_mapping(&self, identity: Option<&irmind_domain::MappingIdentityV1>) -> bool {
        identity.is_some_and(|identity| self.mapping.matches(identity))
    }

    pub const fn matches_rows(&self, accepted: u64, rejected: u64) -> bool {
        accepted == self.row_count && rejected == self.rejected_rows
    }

    pub(super) const fn has_no_rows(&self) -> bool {
        self.row_count == 0
    }

    pub(super) fn matches_manifest(&self, source: &irmind_domain::SourceManifestV2) -> bool {
        source.source.copied
            && source.source.sha256.as_str() == self.capture_sha256
            && source.source.size == self.capture_bytes
            && source.source.source == self.capture_path()
            && source.parser_id == self.decoder.id
            && source.parser_version == self.decoder.version
            && source.rejected_records == self.rejected_rows
    }

    pub fn source_reference(&self) -> Result<irmind_domain::SourceReferenceV1, SourceQueryError> {
        let acquisition = irmind_domain::EvidenceHash::parse(&self.content_id()?)
            .map_err(|_| SourceQueryError::Invalid)?;
        irmind_domain::SourceReferenceV1::try_new(
            &self.capture_path(),
            irmind_domain::SourceKind::ToolResult,
            Some(acquisition),
        )
        .map_err(|_| SourceQueryError::Invalid)
    }

    pub fn verify_capture(&self, summary: &QueryCaptureSummary) -> Result<(), SourceQueryError> {
        let causes = ["provider_partial", "local_limit", "cancelled", "rejected"];
        let missing_cause = causes.iter().enumerate().any(|(index, reason)| {
            summary.completeness_mask & (1 << (index + 1)) != 0
                && !self.completeness.iter().any(|value| value == reason)
        });
        if summary.capture_sha256.as_str() != self.capture_sha256
            || summary.plan.as_str() != self.plan
            || summary.page_commitment.as_str() != self.page_commitment
            || summary.page_count != self.page_count
            || summary.bytes != self.capture_bytes
            || summary.rows != self.row_count + self.rejected_rows
            || summary.decoder.id() != self.decoder.id
            || summary.decoder.version() != self.decoder.version
            || missing_cause
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQuerySettlementV1 {
    version: u64,
    case_id: String,
    plan: String,
    reservation: String,
    execution: String,
    result: Option<String>,
    scan_charged: Option<u64>,
    retained_rows: u64,
    retained_bytes: u64,
    usage: SourceQueryUsage,
    uncertainty: Vec<String>,
    at: QueryTime,
}

impl SourceQuerySettlementV1 {
    pub(super) fn reservation(&self) -> &str {
        &self.reservation
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        let record: Self = decode_record(bytes)?;
        validate_identity(record.version, &record.case_id, None)?;
        validate_links(&[&record.plan, &record.reservation, &record.execution])?;
        if record.result.as_deref().is_some_and(|value| !digest(value))
            || (record.result.is_none()
                && (record.retained_rows != 0 || record.retained_bytes != 0))
            || record.retained_rows > QUERY_MAX_ROWS
            || record.retained_bytes > QUERY_MAX_BYTES
            || !bounded_reasons(&record.uncertainty)
        {
            return Err(SourceQueryError::Invalid);
        }
        match record.usage.query_price_basis {
            QueryAccounting::ScanPriced
                if record.scan_charged.is_none()
                    || record.scan_charged != record.usage.scanned_bytes =>
            {
                return Err(SourceQueryError::Unresolved);
            }
            QueryAccounting::AnalyticsNoQueryCharge
                if record.scan_charged.is_some()
                    || record.usage.scanned_bytes.is_some()
                    || record.usage.processed_bytes.is_some()
                    || record.usage.billed_bytes.is_some() =>
            {
                return Err(SourceQueryError::Invalid);
            }
            _ => {}
        }
        Ok(record)
    }

    pub fn content_id(&self) -> Result<String, SourceQueryError> {
        query_content_id("irmind-source-query-settlement-v1", self)
    }
}

#[derive(Clone, Copy)]
pub struct SignedSourceQuerySettlement<'a> {
    pub observations: &'a [&'a SignedEntry],
    pub result: Option<(&'a SignedEntry, &'a QueryCaptureSummary)>,
    pub settlement: &'a SignedEntry,
}

impl SourceQueryBroker {
    /// Reconcile the accounting from authenticated earlier receipts and verified
    /// case-owned capture bytes. The caller serializes the durable append.
    pub fn settle_authenticated(
        &mut self,
        records: SignedSourceQuerySettlement<'_>,
        principal: &AgentId,
        verifier: &dyn Verifier,
    ) -> Result<(), AppError> {
        self.settle_records(
            records.observations,
            records.result.map(|(entry, _)| entry),
            records.settlement,
            principal,
            verifier,
            |result| {
                let (_, capture) = records.result.ok_or(SourceQueryError::Invalid)?;
                Ok(result.verify_capture(capture)?)
            },
        )?;
        Ok(())
    }

    /// Offline replay first authenticates the signed inventory. It must then
    /// verify each capture against that inventory before accepting the case.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn settle_records(
        &mut self,
        observations: &[&SignedEntry],
        result_entry: Option<&SignedEntry>,
        settlement_entry: &SignedEntry,
        principal: &AgentId,
        verifier: &dyn Verifier,
        check_capture: impl FnOnce(&SourceQueryResultV1) -> Result<(), AppError>,
    ) -> Result<Option<SourceQueryResultV1>, AppError> {
        let principal = Actor::Agent(principal.clone());
        verify_entry(
            settlement_entry,
            self.case(),
            AuditEventKind::SourceQuerySettlementV1,
            &principal,
            verifier,
        )?;
        let settlement = SourceQuerySettlementV1::decode(settlement_entry.payload.as_bytes())?;
        let pending = self.pending(&settlement.reservation)?;
        let (execution, execution_seq) =
            verify_observations(observations, self.case(), pending, &principal, verifier)?;
        let execution_id = execution.content_id()?;
        if execution.phase != Phase::Terminal
            || execution.status == Status::Unknown
            || settlement.case_id != self.case().as_str()
            || execution.case_id != settlement.case_id
            || execution.plan != pending.plan
            || settlement.plan != pending.plan
            || settlement.reservation != execution.reservation
            || settlement.execution != execution_id
            || settlement.usage != execution.usage
            || settlement.at.as_str() < execution.observed_at.as_str()
            || execution_seq >= settlement_entry.seq
        {
            return Err(SourceQueryError::Unresolved.into());
        }
        let result = match (settlement.result.as_deref(), result_entry) {
            (Some(expected), Some(entry)) => {
                verify_entry(
                    entry,
                    self.case(),
                    AuditEventKind::SourceQueryResultV1,
                    &principal,
                    verifier,
                )?;
                let result = SourceQueryResultV1::decode(entry.payload.as_bytes())?;
                if result.content_id()? != expected
                    || result.case_id != settlement.case_id
                    || result.plan != settlement.plan
                    || result.reservation != settlement.reservation
                    || result.execution != execution_id
                    || result.capture_bytes != settlement.retained_bytes
                    || result.row_count + result.rejected_rows != settlement.retained_rows
                    || entry.seq <= execution_seq
                    || entry.seq >= settlement_entry.seq
                    || result.at.as_str() < execution.observed_at.as_str()
                    || result.at.as_str() > settlement.at.as_str()
                    || result.decoder != pending.decoder
                    || result.mapping != pending.mapping
                {
                    return Err(SourceQueryError::Invalid.into());
                }
                check_capture(&result)?;
                Some(result)
            }
            (None, None) => None,
            _ => return Err(SourceQueryError::Invalid.into()),
        };
        self.settle(
            &settlement.reservation,
            settlement.scan_charged,
            settlement.retained_rows,
            settlement.retained_bytes,
        )?;
        Ok(result)
    }
}

pub(super) fn verify_observations(
    entries: &[&SignedEntry],
    case: &crate::CaseId,
    hold: &SourceQueryHold,
    principal: &Actor,
    verifier: &dyn Verifier,
) -> Result<(SourceQueryExecutionV1, u64), AppError> {
    let mut previous: Option<SourceQueryExecutionV1> = None;
    let mut seq = hold.reservation_seq;
    for entry in entries {
        verify_entry(
            entry,
            case,
            AuditEventKind::SourceQueryExecutionV1,
            principal,
            verifier,
        )?;
        let observation = SourceQueryExecutionV1::decode(entry.payload.as_bytes())?;
        if entry.seq <= seq
            || observation.case_id != case.as_str()
            || observation.plan != hold.plan
            || observation.reservation != hold.id()
            || observation.attempt != hold.attempt
            || observation.usage.query_price_basis != hold.accounting
        {
            return Err(SourceQueryError::Invalid.into());
        }
        match &previous {
            None if observation.phase == Phase::Intent
                && Some(entry.seq) == hold.reservation_seq.checked_add(1)
                && Some(entry.hash) == hold.intent_hash => {}
            Some(prior)
                if observation.phase != Phase::Intent
                    && observation.previous.as_deref() == Some(prior.content_id()?.as_str())
                    && observation.execution_key == prior.execution_key
                    && observation.started_at == prior.started_at
                    && observation.observed_at.as_str() >= prior.observed_at.as_str()
                    && prior
                        .provider_id
                        .as_ref()
                        .is_none_or(|id| observation.provider_id.as_ref() == Some(id))
                    && ((prior.phase < Phase::Terminal && observation.phase >= prior.phase)
                        || prior.status == Status::Unknown) => {}
            _ => return Err(SourceQueryError::Invalid.into()),
        }
        seq = entry.seq;
        previous = Some(observation);
    }
    Ok((previous.ok_or(SourceQueryError::Unresolved)?, seq))
}

fn validate_links(values: &[&str]) -> Result<(), SourceQueryError> {
    if values.iter().all(|value| digest(value)) {
        Ok(())
    } else {
        Err(SourceQueryError::Invalid)
    }
}

fn bounded_reasons(values: &[String]) -> bool {
    values.len() <= 32 && values.iter().all(|value| text(value, 256))
}
