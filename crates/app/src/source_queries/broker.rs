use super::{
    QueryAccounting, SourceQueryAllocationV1, SourceQueryApprovalV1, SourceQueryError,
    SourceQueryPlanV1, SourceQueryReservationV1,
};
use irmind_domain::{CaseId, CaseScope};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceQueryResources {
    pub scan_bytes: u64,
    pub retained_rows: u64,
    pub retained_bytes: u64,
}

impl SourceQueryResources {
    fn add(self, other: Self) -> Result<Self, SourceQueryError> {
        Ok(Self {
            scan_bytes: self
                .scan_bytes
                .checked_add(other.scan_bytes)
                .ok_or(SourceQueryError::Budget)?,
            retained_rows: self
                .retained_rows
                .checked_add(other.retained_rows)
                .ok_or(SourceQueryError::Budget)?,
            retained_bytes: self
                .retained_bytes
                .checked_add(other.retained_bytes)
                .ok_or(SourceQueryError::Budget)?,
        })
    }

    fn fits(self, limit: SourceQueryAllocationV1) -> bool {
        self.scan_bytes <= limit.scan_bytes.unwrap_or(0)
            && self.retained_rows <= limit.retained_rows
            && self.retained_bytes <= limit.retained_bytes
    }
}

#[derive(Clone)]
pub struct SourceQueryHold {
    id: String,
    pub(super) plan: String,
    pub(super) attempt: u64,
    pub(super) reservation_seq: u64,
    pub(super) intent_hash: Option<[u8; 32]>,
    pub(super) decoder: super::receipts::Decoder,
    pub(super) mapping: super::receipts::Mapping,
    pub(super) accounting: QueryAccounting,
    source: (String, String, String),
    resources: SourceQueryResources,
}

impl SourceQueryHold {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn resources(&self) -> SourceQueryResources {
        self.resources
    }
}

/// Accounting state rebuilt from case records. Callers must authenticate the
/// receipts, hold the case lock, and persist reservation/intent before dispatch.
/// A hold represents capacity accounting and cannot authorize an executor.
pub struct SourceQueryBroker {
    case: CaseId,
    allocation: SourceQueryAllocationV1,
    ceiling: SourceQueryAllocationV1,
    revision: u64,
    used: SourceQueryResources,
    held: SourceQueryResources,
    holds: BTreeMap<String, SourceQueryHold>,
    plans: BTreeSet<String>,
    settled: BTreeSet<String>,
}

impl SourceQueryBroker {
    pub fn new(
        case: CaseId,
        allocation: SourceQueryAllocationV1,
        ceiling: SourceQueryAllocationV1,
    ) -> Result<Self, SourceQueryError> {
        if !allocation.within(ceiling) {
            return Err(SourceQueryError::Budget);
        }
        Ok(Self {
            case,
            allocation,
            ceiling,
            revision: 0,
            used: SourceQueryResources::default(),
            held: SourceQueryResources::default(),
            holds: BTreeMap::new(),
            plans: BTreeSet::new(),
            settled: BTreeSet::new(),
        })
    }

    pub fn change_allocation(
        &mut self,
        revision: u64,
        allocation: SourceQueryAllocationV1,
    ) -> Result<(), SourceQueryError> {
        if self.revision.checked_add(1) != Some(revision)
            || !allocation.within(self.ceiling)
            || !self.used.add(self.held)?.fits(allocation)
            || (!allocation.analytics_allowed
                && self
                    .holds
                    .values()
                    .any(|hold| hold.accounting == QueryAccounting::AnalyticsNoQueryCharge))
        {
            return Err(SourceQueryError::Budget);
        }
        self.allocation = allocation;
        self.revision = revision;
        Ok(())
    }

    pub const fn used(&self) -> SourceQueryResources {
        self.used
    }

    pub const fn held(&self) -> SourceQueryResources {
        self.held
    }

    /// Allocate both private files before receiving any capture page. The caller
    /// holds the case lock and has reconstructed this broker from the case chain.
    pub fn prepare_capture_spools(
        &self,
        reservation: &str,
        audit: &dyn crate::AuditLog,
        store: &dyn crate::LargeCaseStore,
        cancel: &crate::CancellationToken,
    ) -> Result<
        (
            super::QueryCaptureWriter<tempfile::NamedTempFile>,
            tempfile::NamedTempFile,
        ),
        crate::AppError,
    > {
        if cancel.is_cancelled() {
            return Err(crate::AppError::Cancelled);
        }
        let hold = self.pending(reservation)?;
        let index = usize::try_from(hold.reservation_seq).map_err(|_| SourceQueryError::Invalid)?;
        // The submit intent immediately follows the reservation. A tentative
        // hold prepared before append may not allocate disk or receive pages.
        let entries = audit.entries(&self.case)?;
        let intent = entries.get(index).ok_or(SourceQueryError::Unresolved)?;
        if Some(intent.hash) != hold.intent_hash
            || intent.kind != crate::AuditEventKind::SourceQueryExecutionV1
            || intent.case_id != self.case.as_str()
            || hold.reservation_seq.checked_add(1) != Some(intent.seq)
            || crate::sha256(&intent.canonical()) != intent.hash
        {
            return Err(SourceQueryError::Unresolved.into());
        }
        // Scan debt blocks new reservations. It cannot revoke already
        // admitted retention room.
        let total = self.used.add(self.held)?;
        if total.retained_bytes > self.allocation.retained_bytes
            || total.retained_rows > self.allocation.retained_rows
        {
            return Err(SourceQueryError::Budget.into());
        }
        let limits = hold.resources();
        let plan = irmind_domain::EvidenceHash::parse(&hold.plan)
            .map_err(|_| SourceQueryError::Invalid)?;
        let decoder = irmind_domain::SourceDecoderIdentityV1::try_new(
            &hold.decoder.id,
            &hold.decoder.version,
        )
        .map_err(|_| SourceQueryError::Invalid)?;
        let staged = store.create_object_spool(&self.case, 2 * limits.retained_bytes)?;
        let output = store.create_object_spool(&self.case, limits.retained_bytes)?;
        let writer = super::QueryCaptureWriter::new(
            staged,
            plan,
            decoder,
            limits.retained_bytes,
            limits.retained_rows,
        )?;
        Ok((writer, output))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn reserve(
        &mut self,
        plan: &SourceQueryPlanV1,
        receipt: &SourceQueryReservationV1,
        approval: Option<&SourceQueryApprovalV1>,
        case_scope: &CaseScope,
        organization_scope: &CaseScope,
        scan_threshold: u64,
        policy_requires_approval: bool,
        reservation_seq: u64,
        intent_hash: Option<[u8; 32]>,
    ) -> Result<SourceQueryHold, SourceQueryError> {
        if !self.allocation.enabled {
            return Err(SourceQueryError::Disabled);
        }
        if plan.allocation_revision() != self.revision {
            return Err(SourceQueryError::Budget);
        }
        plan.validate_scope(&self.case, case_scope, organization_scope)?;
        let plan_id = plan.content_id()?;
        let approval_id = match approval {
            Some(approval) if approval.permits(plan, &plan_id) => Some(approval.content_id()?),
            None if !plan.requires_approval(scan_threshold, policy_requires_approval) => None,
            _ => return Err(SourceQueryError::Approval),
        };
        receipt.check(plan, approval_id.as_deref())?;
        let id = receipt.content_id()?;
        let source = plan.source();
        let source = (
            source.module().to_owned(),
            source.owner().to_owned(),
            source.location().to_owned(),
        );
        let limits = plan.limits();
        if self.plans.contains(&plan_id)
            || self
                .holds
                .values()
                .filter(|hold| hold.source == source)
                .count() as u64
                >= limits.concurrency
        {
            return Err(SourceQueryError::Unresolved);
        }
        let accounting = plan.accounting();
        if accounting == QueryAccounting::AnalyticsNoQueryCharge
            && !self.allocation.analytics_allowed
        {
            return Err(SourceQueryError::Budget);
        }
        let resources = SourceQueryResources {
            scan_bytes: limits.scan_bytes.unwrap_or(0),
            retained_rows: limits.rows,
            retained_bytes: limits.retained_bytes,
        };
        let total_reserved = self.held.add(resources)?;
        if !self.used.add(total_reserved)?.fits(self.allocation) {
            return Err(SourceQueryError::Budget);
        }
        let hold = SourceQueryHold {
            id,
            plan: plan_id.clone(),
            attempt: plan.attempt,
            reservation_seq,
            intent_hash,
            decoder: plan.decoder.clone(),
            mapping: plan.mapping.clone(),
            source,
            accounting,
            resources,
        };
        self.holds.insert(hold.id.clone(), hold.clone());
        self.plans.insert(plan_id);
        self.held = total_reserved;
        Ok(hold)
    }

    pub(super) const fn case(&self) -> &CaseId {
        &self.case
    }

    /// Apply the accounting from a verified terminal settlement. Unknown priced
    /// scans keep their hold. Known scan overruns are charged in full.
    pub(super) fn settle(
        &mut self,
        id: &str,
        scanned_bytes: Option<u64>,
        retained_rows: u64,
        retained_bytes: u64,
    ) -> Result<(), SourceQueryError> {
        if self.settled.contains(id) {
            return Err(SourceQueryError::AlreadySettled);
        }
        let hold = self.holds.get(id).ok_or(SourceQueryError::Invalid)?;
        let scan_bytes = match (hold.accounting, scanned_bytes) {
            (QueryAccounting::ScanPriced, Some(bytes)) => bytes,
            (QueryAccounting::AnalyticsNoQueryCharge, None) => 0,
            _ => return Err(SourceQueryError::Unresolved),
        };
        if retained_rows > hold.resources.retained_rows
            || retained_bytes > hold.resources.retained_bytes
        {
            return Err(SourceQueryError::Budget);
        }
        let used = self.used.add(SourceQueryResources {
            scan_bytes,
            retained_rows,
            retained_bytes,
        })?;
        self.held.scan_bytes -= hold.resources.scan_bytes;
        self.held.retained_rows -= hold.resources.retained_rows;
        self.held.retained_bytes -= hold.resources.retained_bytes;
        self.used = used;
        self.holds.remove(id);
        self.settled.insert(id.to_owned());
        Ok(())
    }

    pub(super) fn pending(&self, id: &str) -> Result<&SourceQueryHold, SourceQueryError> {
        if self.settled.contains(id) {
            return Err(SourceQueryError::AlreadySettled);
        }
        self.holds.get(id).ok_or(SourceQueryError::Invalid)
    }
}
