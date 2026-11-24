//! Resolve reviewed finding citations against a single authenticated checkpoint.
use super::{
    EntityDetails, ReportDocument, ReportDocumentFormat, ReportDocumentLanguage, ReportLimitation,
    ReportLocator, ReportStatement,
};
use crate::{
    AppError, AuditEventKind, CancellationToken, CaseId, Engine, SignedEntry,
    source_queries::SourceQueryResultV1,
    v10_proofs::{
        CaseCheckpointV1, ReportCitationsV1, V10CheckpointView, V10Citation, V10RowReference,
    },
};
use irmind_domain::{EvidenceHash, ParquetArtifact, SourceManifestV2};
use std::collections::BTreeSet;

impl Engine<'_> {
    pub fn cited_report_inputs(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<(Vec<SignedEntry>, Vec<super::Finding>), AppError> {
        let _lock = self.repo.lock_case(id)?;
        self.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.audit_log.entries(id)?;
        let findings = self.findings_unlocked(id, &entries)?;
        Ok((entries, findings))
    }

    /// Render already-confirmed findings using the exact source and row from
    /// the review. A bad citation or confirmation invalidates the selection.
    /// This builds an unsigned preview of row citations.
    pub fn render_cited_findings(
        &self,
        id: &CaseId,
        checkpoint: &CaseCheckpointV1,
        citations: &ReportCitationsV1,
        language: ReportDocumentLanguage,
        format: ReportDocumentFormat,
        mut verify_row: impl FnMut(&ParquetArtifact, V10RowReference) -> Result<(), AppError>,
    ) -> Result<Vec<u8>, AppError> {
        if checkpoint.case_id != *id {
            return Err(AppError::InvalidChain(checkpoint.sequence));
        }
        let _lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        let case = self.repo.get_case(id)?;
        let entries = self.audit_log.entries(id)?;
        let view = V10CheckpointView::resolve(&entries, checkpoint)?;
        let length = usize::try_from(checkpoint.sequence)
            .map_err(|_| AppError::InvalidChain(checkpoint.sequence))?;
        let prefix = &entries[..length];
        let findings = self.findings_unlocked(id, prefix)?;
        let mut resolved = Vec::with_capacity(citations.0.len());
        for selection in &citations.0 {
            view.confirmed_finding(selection.confirmation, &selection.finding_id)?;
            let invalid = || AppError::InvalidChain(selection.confirmation.sequence);
            let finding = findings
                .iter()
                .find(|finding| finding.id == selection.finding_id && finding.confirmed)
                .ok_or_else(invalid)?;
            let Some(EntityDetails::Timeline {
                record_index: Some(record),
                ..
            }) = &finding.details
            else {
                return Err(invalid());
            };
            if selection.citations.len() != 1 {
                return Err(invalid());
            }
            let V10Citation::Row(reference) = selection.citations[0] else {
                return Err(invalid());
            };
            let evidence = EvidenceHash::from_bytes(reference.source.evidence_sha256);
            if evidence.as_str() != finding.evidence_hash || reference.record != *record as u64 {
                return Err(invalid());
            }
            verify_row(&view.row_artifact(reference)?, reference)?;
            resolved.push((
                finding.value.as_str(),
                [ReportLocator::Record {
                    evidence,
                    record: reference.record,
                }],
            ));
        }
        let confirmed = resolved
            .iter()
            .map(|(text, citations)| ReportStatement {
                text,
                selected_by_model: false,
                citations,
            })
            .collect::<Vec<_>>();
        let coverage = PreviewCoverage::from_entries(prefix)?;
        ReportDocument {
            case_id: id,
            title: &case.title,
            confirmed: &confirmed,
            analyst: None,
            limitations: &coverage.limitations(),
        }
        .render(language, format)
    }
}

struct PreviewCoverage {
    unknown_sources: Vec<String>,
    query_limits: Vec<EvidenceHash>,
}

impl PreviewCoverage {
    fn from_entries(entries: &[SignedEntry]) -> Result<Self, AppError> {
        let mut captures = BTreeSet::new();
        let mut query_limits = Vec::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceQueryResultV1)
        {
            let result = SourceQueryResultV1::decode(entry.payload.as_bytes())?;
            captures.insert(result.capture_identity().0.to_owned());
            if result.limit_notice().is_some() {
                query_limits.push(EvidenceHash::from_bytes(entry.hash));
            }
        }
        let mut unknown_sources = Vec::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        {
            let source = SourceManifestV2::decode(&entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?
                .source;
            if !source.copied && !captures.contains(source.sha256.as_str()) {
                unknown_sources.push(source.source);
            }
        }
        Ok(Self {
            unknown_sources,
            query_limits,
        })
    }

    fn limitations(&self) -> Vec<ReportLimitation<'_>> {
        self.unknown_sources
            .iter()
            .map(|source| ReportLimitation::SourceAvailabilityUnknown(source))
            .chain(
                self.query_limits
                    .iter()
                    .map(|receipt| ReportLimitation::QueryLimit { receipt }),
            )
            .collect()
    }
}
