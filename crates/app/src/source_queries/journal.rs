use super::{
    BudgetReplay, QUERY_CASE_MAX_BYTES, QUERY_CASE_MAX_ROWS, SignedSourceQueryAdmission,
    SourceQueryAllocationV1, SourceQueryApprovalV1, SourceQueryAuthority, SourceQueryBroker,
    SourceQueryExecutionV1, SourceQueryPlanV1, SourceQueryReservationV1, SourceQueryResources,
    SourceQueryResultV1, SourceQuerySettlementV1,
    admission::{adopted_threshold, verify_entry},
    completion::verify_observations,
};
use crate::{
    Actor, AppError, AuditEventKind, CancellationToken, CaseId, CaseScope, SignedEntry,
    SignedOperation, Verifier,
    engine::{ScopeChangedEvent, current_case_creation},
};
use irmind_domain::{AgentId, SourceKind, SourceManifestV2, SourceRecordSetV1};
use std::collections::{BTreeMap, BTreeSet};

struct Planned<'a> {
    signed: &'a SignedEntry,
    operation: &'a SignedOperation,
    principal: AgentId,
}

struct Pending<'a> {
    principal: AgentId,
    observations: Vec<&'a SignedEntry>,
    result: Option<&'a SignedEntry>,
}

/// Rebuilt from authenticated case entries while holding the case lock or
/// from a verified portable chain. This inventory confers no network authority.
pub struct SourceQueryJournal<'a> {
    pub(super) broker: SourceQueryBroker,
    operations: BTreeMap<[u8; 32], &'a SignedOperation>,
    captures: BTreeMap<String, Capture>,
}

struct Capture {
    receipt: SourceQueryResultV1,
    result_seq: u64,
    settlement_seq: u64,
}

impl<'a> SourceQueryJournal<'a> {
    pub fn replay(
        entries: &'a [SignedEntry],
        operations: &'a [SignedOperation],
        verifier: &dyn Verifier,
        cancel: &CancellationToken,
    ) -> Result<Self, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let first = entries.first().ok_or(AppError::InvalidChain(0))?;
        let case = CaseId::parse(&first.case_id).map_err(|_| AppError::InvalidChain(1))?;
        let created = current_case_creation(first)?;
        let allocation = created.source_queries;
        // Replay recognizes historical signed budgets within the wire
        // bounds. It cannot grant resources under today's policy.
        let maximum = SourceQueryAllocationV1 {
            enabled: true,
            analytics_allowed: true,
            scan_bytes: Some(u64::MAX),
            retained_rows: QUERY_CASE_MAX_ROWS,
            retained_bytes: QUERY_CASE_MAX_BYTES,
        };
        let mut replay = Replay {
            journal: Self {
                broker: SourceQueryBroker::new(case, allocation, maximum)?,
                operations: BTreeMap::new(),
                captures: BTreeMap::new(),
            },
            adopted: operations
                .iter()
                .map(|item| (crate::hex(&item.hash), item))
                .collect(),
            scope: CaseScope::parse(&created.scope).map_err(|_| AppError::InvalidChain(1))?,
            plans: BTreeMap::new(),
            approvals: BTreeMap::new(),
            decided: BTreeSet::new(),
            pending: BTreeMap::new(),
            verifier,
        };
        let mut budget = BudgetReplay::new(first, allocation);
        for (index, entry) in entries.iter().enumerate().skip(1) {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            budget.accept(entry)?;
            match entry.kind {
                AuditEventKind::SourceQueryBudgetV1 => {
                    let (revision, allocation) = budget.current();
                    replay
                        .journal
                        .broker
                        .change_allocation(revision, allocation)?;
                }
                AuditEventKind::CaseScopeChanged => {
                    let change: ScopeChangedEvent = serde_json::from_str(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    replay.scope = CaseScope::parse(&change.new_scope)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                }
                _ => replay.accept(entry, entries.get(index + 1))?,
            }
        }
        replay.finish()
    }

    pub fn captures(&self) -> impl ExactSizeIterator<Item = &SourceQueryResultV1> {
        self.captures.values().map(|capture| &capture.receipt)
    }

    pub fn contains_capture(&self, hash: &irmind_domain::EvidenceHash) -> bool {
        self.captures.contains_key(hash.as_str())
    }

    pub fn adoptions(&self) -> impl ExactSizeIterator<Item = &SignedOperation> {
        self.operations.values().copied()
    }

    pub fn held(&self) -> SourceQueryResources {
        self.broker.held()
    }

    pub fn used(&self) -> SourceQueryResources {
        self.broker.used()
    }

    pub fn verify_capture_files(
        &self,
        store: &dyn crate::LargeCaseStore,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        for capture in self.captures() {
            let (digest, bytes) = capture.capture_identity();
            let hash = irmind_domain::EvidenceHash::parse(digest)
                .map_err(|_| super::SourceQueryError::Invalid)?;
            let reader =
                store.open_source_query_capture(self.broker.case(), &hash, bytes, cancel)?;
            capture.verify_capture(&super::verify_query_capture(reader, cancel)?)?;
        }
        Ok(())
    }

    /// Every acquired input is bound to the exact query result and a manifest
    /// in the same publication group. A file with a similar name grants no
    /// query provenance. The regular artifact verifier checks mapping receipts.
    pub fn verify_source_links(&self, entries: &[SignedEntry]) -> Result<(), AppError> {
        let mut manifests = BTreeSet::new();
        let mut source_sets = BTreeSet::new();
        for entry in entries {
            let invalid = || AppError::InvalidChain(entry.seq);
            match entry.kind {
                AuditEventKind::SourceManifestV2 if !self.captures.is_empty() => {
                    let source = SourceManifestV2::decode(&entry.payload).map_err(|_| invalid())?;
                    let hash = source.source.sha256.as_str();
                    if let Some(capture) = self.captures.get(hash)
                        && (!capture.contains(entry.seq)
                            || !capture.receipt.matches_manifest(&source)
                            || !manifests.insert(hash.to_owned()))
                    {
                        return Err(invalid());
                    }
                }
                AuditEventKind::SourceRecordSetV1 => {
                    let source =
                        SourceRecordSetV1::decode(&entry.payload).map_err(|_| invalid())?;
                    if source.reference().kind() == SourceKind::ToolResult {
                        let hash = source.source().as_str();
                        let capture = self.captures.get(hash).ok_or_else(invalid)?;
                        if !capture.contains(entry.seq)
                            || !manifests.contains(hash)
                            || capture.receipt.source_reference()? != *source.reference()
                            || !capture
                                .receipt
                                .matches_rows(source.records(), source.rejected())
                            || !source_sets.insert(hash.to_owned())
                        {
                            return Err(invalid());
                        }
                    } else if self.captures.contains_key(source.source().as_str()) {
                        return Err(invalid());
                    }
                }
                _ => {}
            }
        }
        for (hash, capture) in &self.captures {
            if !manifests.contains(hash)
                || (!capture.receipt.has_no_rows() && !source_sets.contains(hash))
            {
                return Err(AppError::InvalidChain(capture.result_seq));
            }
        }
        Ok(())
    }
}

impl Capture {
    fn contains(&self, seq: u64) -> bool {
        self.result_seq < seq && seq < self.settlement_seq
    }
}

struct Replay<'a, 'v> {
    journal: SourceQueryJournal<'a>,
    adopted: BTreeMap<String, &'a SignedOperation>,
    scope: CaseScope,
    plans: BTreeMap<String, Planned<'a>>,
    approvals: BTreeMap<String, &'a SignedEntry>,
    decided: BTreeSet<String>,
    pending: BTreeMap<String, Pending<'a>>,
    verifier: &'v dyn Verifier,
}

impl<'a> Replay<'a, '_> {
    fn accept(
        &mut self,
        entry: &'a SignedEntry,
        next: Option<&'a SignedEntry>,
    ) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        match entry.kind {
            AuditEventKind::SourceQueryPlanV1 => self.plan(entry)?,
            AuditEventKind::SourceQueryApprovalV1 => self.approve(entry)?,
            AuditEventKind::SourceQueryReservationV1 => {
                self.reserve(entry, next.ok_or_else(invalid)?)?;
            }
            AuditEventKind::SourceQueryExecutionV1 => {
                let observation = SourceQueryExecutionV1::decode(entry.payload.as_bytes())?;
                let pending = self
                    .pending
                    .get_mut(observation.reservation())
                    .ok_or_else(invalid)?;
                if pending.result.is_some() {
                    return Err(invalid());
                }
                pending.observations.push(entry);
            }
            AuditEventKind::SourceQueryResultV1 => {
                let result = SourceQueryResultV1::decode(entry.payload.as_bytes())?;
                let pending = self
                    .pending
                    .get_mut(result.reservation())
                    .ok_or_else(invalid)?;
                if pending.result.replace(entry).is_some() {
                    return Err(invalid());
                }
            }
            AuditEventKind::SourceQuerySettlementV1 => self.settle(entry)?,
            _ => {}
        }
        Ok(())
    }

    fn plan(&mut self, entry: &'a SignedEntry) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        let Actor::Agent(principal) = &entry.actor else {
            return Err(invalid());
        };
        let case = self.journal.broker.case();
        verify_entry(entry, case, entry.kind, &entry.actor, self.verifier)?;
        let record = SourceQueryPlanV1::decode(entry.payload.as_bytes())?;
        record.validate_scope(case, &self.scope, &self.scope)?;
        let operation = *self.adopted.get(record.adoption()).ok_or_else(invalid)?;
        adopted_threshold(&record, operation, self.verifier)?;
        self.journal.operations.insert(operation.hash, operation);
        if self
            .plans
            .insert(
                record.content_id()?,
                Planned {
                    signed: entry,
                    operation,
                    principal: principal.clone(),
                },
            )
            .is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn approve(&mut self, entry: &'a SignedEntry) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        let case = self.journal.broker.case();
        verify_entry(entry, case, entry.kind, &Actor::Analyst, self.verifier)?;
        let approval = SourceQueryApprovalV1::decode(entry.payload.as_bytes())?;
        if approval.case_id() != case.as_str()
            || !self.plans.contains_key(approval.plan())
            || !self.decided.insert(approval.plan().into())
        {
            return Err(invalid());
        }
        self.approvals.insert(approval.content_id()?, entry);
        Ok(())
    }

    fn reserve(&mut self, entry: &'a SignedEntry, intent: &'a SignedEntry) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        let record = SourceQueryReservationV1::decode(entry.payload.as_bytes())?;
        let plan = self.plans.remove(record.plan()).ok_or_else(invalid)?;
        let approval = match record.approval() {
            Some(id) => Some(*self.approvals.get(id).ok_or_else(invalid)?),
            None if !self.decided.contains(record.plan()) => None,
            None => return Err(invalid()),
        };
        let hold = self.journal.broker.reserve_authenticated(
            SignedSourceQueryAdmission {
                plan: plan.signed,
                approval,
                reservation: entry,
                intent,
                configuration: plan.operation,
            },
            SourceQueryAuthority {
                principal: &plan.principal,
                case_scope: &self.scope,
                organization_scope: &self.scope,
                requires_policy_approval: false,
                verifier: self.verifier,
            },
        )?;
        self.pending.insert(
            hold.id().into(),
            Pending {
                principal: plan.principal,
                observations: Vec::new(),
                result: None,
            },
        );
        Ok(())
    }

    fn settle(&mut self, entry: &'a SignedEntry) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        let settlement = SourceQuerySettlementV1::decode(entry.payload.as_bytes())?;
        let pending = self
            .pending
            .remove(settlement.reservation())
            .ok_or_else(invalid)?;
        if let Some(receipt) = self.journal.broker.settle_records(
            &pending.observations,
            pending.result,
            entry,
            &pending.principal,
            self.verifier,
            |_| Ok(()),
        )? {
            let hash = receipt.capture_identity().0.into();
            let result_seq = pending.result.ok_or_else(invalid)?.seq;
            let capture = Capture {
                receipt,
                result_seq,
                settlement_seq: entry.seq,
            };
            if self.journal.captures.insert(hash, capture).is_some() {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<SourceQueryJournal<'a>, AppError> {
        for (id, pending) in self.pending {
            if let Some(result) = pending.result {
                return Err(AppError::InvalidChain(result.seq));
            }
            let broker = &self.journal.broker;
            verify_observations(
                &pending.observations,
                broker.case(),
                broker.pending(&id)?,
                &Actor::Agent(pending.principal),
                self.verifier,
            )?;
        }
        Ok(self.journal)
    }
}
