//! Resolve a signed execution against the existing case and global custody.
use super::{
    SigmaRunV1, V10AuditReference, V10CheckpointView, V10SigmaRunObjects, sigma_pack_operation,
};
use crate::{
    Actor, AppError, AuditEventKind, SignedEntry, SignedOperation,
    source_queries::SourceQueryResultV1,
};
use irmind_domain::EvidenceHash;
use std::collections::BTreeMap;

pub fn sigma_execution(entry: &SignedEntry) -> Result<SigmaRunV1, AppError> {
    let invalid = || AppError::InvalidChain(entry.seq);
    let run = SigmaRunV1::decode(&entry.payload).map_err(|_| invalid())?;
    if entry.kind != AuditEventKind::SigmaRunV1
        || entry.actor != Actor::Analyst
        || entry.origin != "analyst"
        || entry.evidence.is_some()
        || run.checkpoint.case_id.as_str() != entry.case_id
        || run.checkpoint.sequence.checked_add(1) != Some(entry.seq)
        || run.checkpoint.entry_hash != entry.prev
    {
        return Err(invalid());
    }
    Ok(run)
}

impl V10SigmaRunObjects {
    /// The caller authenticates the case prefix and admission signature first.
    pub fn verify_execution_scope(
        &self,
        run: &SigmaRunV1,
        admission: &SignedOperation,
        entries: &[SignedEntry],
    ) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(run.checkpoint.sequence);
        if run.pack_admission != admission.hash || sigma_pack_operation(admission)?.is_none() {
            return Err(invalid());
        }
        let view = V10CheckpointView::resolve(entries, &run.checkpoint)?;
        if view.active_artifact_inventory()? != run.artifact_inventory {
            return Err(invalid());
        }
        for source in &self.selected_sources.0 {
            view.source(*source)?;
        }
        for &(source, count) in &self.unavailable_by_source {
            if count > view.records_for_source(source)? {
                return Err(invalid());
            }
        }
        let inherited = sigma_query_limits(view.entries())?;
        for matched in &self.results.matches {
            let evidence = EvidenceHash::from_bytes(matched.row.source.evidence_sha256);
            if inherited.get(evidence.as_str()).copied() != matched.query_limit {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

pub fn sigma_query_limits(
    entries: &[SignedEntry],
) -> Result<BTreeMap<String, V10AuditReference>, AppError> {
    let mut inherited = BTreeMap::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SourceQueryResultV1)
    {
        let capture = SourceQueryResultV1::decode(entry.payload.as_bytes())?;
        if capture.limit_notice().is_some()
            && inherited
                .insert(
                    capture.capture_identity().0.to_owned(),
                    V10AuditReference {
                        sequence: entry.seq,
                        entry_sha256: entry.hash,
                    },
                )
                .is_some()
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
    }
    Ok(inherited)
}

const SIGMA_RUN_WORK: u64 = 1_000_000_000;
const SIGMA_CASE_WORK: u64 = 4 * SIGMA_RUN_WORK;

pub struct SigmaFindingDraft {
    pub title: String,
    pub row: super::V10RowReference,
    pub at: String,
}

pub struct PreparedSigmaExecution<T> {
    pub receipt: SigmaRunV1,
    pub findings: Vec<SigmaFindingDraft>,
    pub material: T,
    pub skipped_rules: usize,
    pub class_coverage: super::SigmaClassCoverage,
    pub skipped_classes: Vec<(String, usize, usize)>,
    pub unavailable_by_source: Vec<(String, u64)>,
    pub indeterminate_by_rule: Vec<(super::SigmaRuleKeyV1, u64)>,
}

pub struct SigmaExecutionSummary {
    pub receipt: SigmaRunV1,
    pub skipped_rules: usize,
    pub class_coverage: super::SigmaClassCoverage,
    pub skipped_classes: Vec<(String, usize, usize)>,
    pub unavailable_by_source: Vec<(String, u64)>,
    pub indeterminate_by_rule: Vec<(super::SigmaRuleKeyV1, u64)>,
}

pub struct SigmaExecutionContext<'a> {
    pub view: V10CheckpointView<'a>,
    pub checkpoint: super::CaseCheckpointV1,
    pub reserved: u64,
}

/// Values frozen by the attended installation/run preview.
pub struct InstalledSigmaRunSelection {
    pub name: String,
    pub installation: [u8; 32],
    pub case_head: [u8; 32],
}

impl crate::Engine<'_> {
    /// Hold the case's exclusive lock across the reservation, scan and append.
    /// Sigma work is local, and nothing is committed until the scan settles.
    pub fn execute_sigma<T>(
        &self,
        case: &crate::CaseId,
        manifest: [u8; 32],
        cancel: &crate::CancellationToken,
        evaluate: impl FnOnce(
            SigmaExecutionContext<'_>,
            &SignedOperation,
        ) -> Result<PreparedSigmaExecution<T>, AppError>,
        commit: impl FnOnce(T, &[SignedEntry], &crate::CancellationToken) -> Result<(), AppError>,
    ) -> Result<SigmaExecutionSummary, AppError> {
        self.execute_sigma_inner(case, manifest, None, cancel, evaluate, commit)
    }

    pub fn execute_installed_sigma<T>(
        &self,
        case: &crate::CaseId,
        manifest: [u8; 32],
        selected: &InstalledSigmaRunSelection,
        cancel: &crate::CancellationToken,
        evaluate: impl FnOnce(SigmaExecutionContext<'_>, &SignedOperation) -> Result<PreparedSigmaExecution<T>, AppError>,
        commit: impl FnOnce(T, &[SignedEntry], &crate::CancellationToken) -> Result<(), AppError>,
    ) -> Result<SigmaExecutionSummary, AppError> {
        self.execute_sigma_inner(case, manifest, Some(selected), cancel, evaluate, commit)
    }

    #[expect(clippy::too_many_arguments, clippy::too_many_lines, reason = "the case lock covers one signed transaction and its proof publication")]
    fn execute_sigma_inner<T>(
        &self,
        case: &crate::CaseId,
        manifest: [u8; 32],
        selected: Option<&InstalledSigmaRunSelection>,
        cancel: &crate::CancellationToken,
        evaluate: impl FnOnce(SigmaExecutionContext<'_>, &SignedOperation) -> Result<PreparedSigmaExecution<T>, AppError>,
        commit: impl FnOnce(T, &[SignedEntry], &crate::CancellationToken) -> Result<(), AppError>,
    ) -> Result<SigmaExecutionSummary, AppError> {
        self.require_attended_analyst("execute Sigma")?;
        let _lock = self.repo.lock_case(case)?;
        if self.repo.get_case(case)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked_cancelable(case, cancel)?;
        let entries = self.audit_log.entries(case)?;
        let edge = entries.last().ok_or(AppError::InvalidChain(0))?;
        // The case lock comes first, as in source-query admission.
        let _installation_lock = if let Some(selected) = selected {
            let lock = self.audit_log.lock_global_operations()?;
            let mut installed = self.sigma_installations()?;
            if edge.hash != selected.case_head || !installed.remove(&selected.name).is_some_and(|(receipt, operation)| {
                receipt.active && receipt.manifest == manifest && operation.hash == selected.installation
            }) {
                return Err(AppError::Policy("Sigma extraction scope or installation changed after review".into()));
            }
            Some(lock)
        } else {
            None
        };
        let checkpoint = super::CaseCheckpointV1 {
            case_id: case.clone(),
            sequence: edge.seq,
            entry_hash: edge.hash,
        };
        let operation = self
            .admitted_sigma_pack(manifest)?
            .ok_or_else(|| AppError::Policy("Sigma pack has no signed admission".into()))?;
        let reserved = reserve_sigma_work(&entries)?;
        let view = V10CheckpointView::resolve(&entries, &checkpoint)?;
        let expected_inventory = view.active_artifact_inventory()?;
        let candidate = evaluate(
            SigmaExecutionContext {
                view,
                checkpoint: checkpoint.clone(),
                reserved,
            },
            &operation,
        )?;
        let mut receipt = candidate.receipt;
        if receipt.checkpoint != checkpoint
            || receipt.pack_admission != operation.hash
            || receipt.artifact_inventory != expected_inventory
            || receipt.reserved_units != reserved
            || receipt.matched_rows != candidate.findings.len() as u64
        {
            return Err(AppError::InvalidChain(edge.seq));
        }
        let mut signed = Vec::new();
        if let Some(selected) = selected {
            let admission = self.sign_sigma_case_admission(case, edge, manifest, selected.installation, &mut receipt)?;
            signed.push(admission);
        } else if super::requires_sigma_case_admission(&receipt.evaluator) {
            return Err(AppError::InvalidChain(edge.seq));
        }
        let payload = receipt
            .encode()
            .map_err(|_| AppError::InvalidChain(edge.seq))?;
        let run = self.signed_entry_after(
            case,
            signed.last().or(Some(edge)),
            crate::AuditOrigin::Analyst,
            AuditEventKind::SigmaRunV1,
            &payload,
            None,
        )?;
        signed.push(run);
        let view = V10CheckpointView::resolve(&entries, &checkpoint)?;
        for draft in candidate.findings {
            let finding = self.sigma_finding(draft, &view)?;
            let body =
                serde_json::to_string(&finding).map_err(|_| AppError::InvalidChain(edge.seq))?;
            signed.push(self.signed_entry_after(
                case,
                signed.last(),
                crate::AuditOrigin::Analyst,
                AuditEventKind::FindingProposed,
                &body,
                Some(&finding.evidence_hash),
            )?);
        }
        let settle_cancel = crate::CancellationToken::new();
        let commit_cancel = if receipt.status == super::SigmaRunStatusV1::Cancelled {
            &settle_cancel
        } else {
            cancel
        };
        commit(candidate.material, &signed, commit_cancel)?;
        Ok(SigmaExecutionSummary {
            receipt,
            skipped_rules: candidate.skipped_rules,
            class_coverage: candidate.class_coverage,
            skipped_classes: candidate.skipped_classes,
            unavailable_by_source: candidate.unavailable_by_source,
            indeterminate_by_rule: candidate.indeterminate_by_rule,
        })
    }

    fn sign_sigma_case_admission(
        &self,
        case: &crate::CaseId,
        edge: &SignedEntry,
        manifest: [u8; 32],
        install: [u8; 32],
        receipt: &mut SigmaRunV1,
    ) -> Result<SignedEntry, AppError> {
        use super::{SigmaCaseRunAdmissionV1, SIGMA_EVALUATOR_V3, SIGMA_EVALUATOR_V4,
            SIGMA_EVALUATOR_V3_CASE_ADMISSION, SIGMA_EVALUATOR_V4_CASE_ADMISSION};
        let evaluator = match receipt.evaluator.as_str() {
            SIGMA_EVALUATOR_V3 => SIGMA_EVALUATOR_V3_CASE_ADMISSION,
            SIGMA_EVALUATOR_V4 => SIGMA_EVALUATOR_V4_CASE_ADMISSION,
            _ => return Err(AppError::InvalidChain(edge.seq)),
        };
        let claim = SigmaCaseRunAdmissionV1 {
            checkpoint: receipt.checkpoint.clone(), installation: Some(install),
            pack_admission: receipt.pack_admission, manifest, artifact_inventory: receipt.artifact_inventory,
            selected_sources: receipt.selected_sources, start_us: receipt.start_utc_micros,
            end_us: receipt.end_utc_micros, field_table: receipt.field_table, compiled_rules: receipt.compiled_rules,
            evaluator: evaluator.into(), reserved_work: receipt.reserved_units,
        };
        let payload = crate::hex(&claim.encode().map_err(|_| AppError::InvalidChain(edge.seq))?);
        let signed = self.signed_entry_after(
            case, Some(edge), crate::AuditOrigin::Analyst, AuditEventKind::SigmaCaseRunAdmissionV1, &payload, None,
        )?;
        receipt.evaluator = evaluator.into();
        receipt.checkpoint.sequence = signed.seq;
        receipt.checkpoint.entry_hash = signed.hash;
        Ok(signed)
    }

    fn sigma_finding(
        &self,
        draft: SigmaFindingDraft,
        view: &V10CheckpointView<'_>,
    ) -> Result<crate::Finding, AppError> {
        let row = draft.row;
        let manifest = view.source(row.source)?;
        view.row_artifact(row)?;
        let title = self.guard.screen(&draft.title)?.text;
        let value = crate::ports::model::output::utf8_prefix(&title, 2_000).to_owned();
        if value.trim().is_empty() || value.contains('\0') {
            return Err(AppError::InvalidChain(row.artifact.entry.sequence));
        }
        let mut at = draft.at;
        if let Some(fraction) = at.find('.') {
            at.truncate(fraction);
            at.push('Z');
        }
        let finding = crate::Finding {
            id: uuid::Uuid::new_v4().to_string(),
            kind: crate::FindingKind::Timeline,
            value,
            evidence_hash: manifest.source.sha256.as_str().to_owned(),
            confirmed: false,
            dismissed: false,
            details: Some(crate::EntityDetails::Timeline {
                at,
                source: manifest.source.source,
                record_index: Some(
                    usize::try_from(row.record)
                        .map_err(|_| AppError::InvalidChain(row.artifact.entry.sequence))?,
                ),
            }),
            source_query_limited: false,
        };
        if !finding.valid_for(&std::collections::BTreeSet::from([finding
            .evidence_hash
            .clone()]))
        {
            return Err(AppError::InvalidChain(row.artifact.entry.sequence));
        }
        Ok(finding)
    }
}

pub fn sigma_remaining_work(entries: &[SignedEntry]) -> Result<u64, AppError> {
    let mut available = SIGMA_CASE_WORK;
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SigmaRunV1)
    {
        let run = sigma_execution(entry)?;
        if run.reserved_units == 0 || run.reserved_units > available.min(SIGMA_RUN_WORK) {
            return Err(AppError::InvalidChain(entry.seq));
        }
        available = available
            .checked_sub(run.used_units)
            .ok_or(AppError::InvalidChain(entry.seq))?;
    }
    Ok(available)
}

fn reserve_sigma_work(entries: &[SignedEntry]) -> Result<u64, AppError> {
    let available = sigma_remaining_work(entries)?;
    if available == 0 {
        return Err(AppError::Policy(
            "This case has exhausted its Sigma work budget".into(),
        ));
    }
    Ok(available.min(SIGMA_RUN_WORK))
}

pub fn parse_sigma_manifest_digest(input: &str) -> Option<[u8; 32]> {
    if !input
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let mut digest = [0; 32];
    hex::decode_to_slice(input, &mut digest).ok()?;
    Some(digest)
}
