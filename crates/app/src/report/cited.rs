//! Resolve reviewed finding citations against a single authenticated checkpoint.
use super::{
    EntityDetails, ReportDocument, ReportDocumentFormat, ReportDocumentLanguage, ReportLocator,
    ReportStatement,
};
use crate::{
    AppError, CaseId, Engine,
    v10_proofs::{
        CaseCheckpointV1, ReportCitationsV1, V10CheckpointView, V10Citation, V10RowReference,
    },
};
use irmind_domain::{EvidenceHash, ParquetArtifact};

impl Engine<'_> {
    /// Render already-confirmed findings using the exact source and row from
    /// the review. A bad citation or confirmation invalidates the selection.
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
        let findings = self.findings_unlocked(id, &entries[..length])?;
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
        ReportDocument {
            case_id: id,
            title: &case.title,
            confirmed: &confirmed,
            analyst: None,
            limitations: &[],
        }
        .render(language, format)
    }
}
