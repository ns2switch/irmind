//! Resolve reviewed finding citations against a single authenticated checkpoint.
use super::{
    EntityDetails, ReportDocument, ReportDocumentFormat, ReportDocumentLanguage, ReportLocator,
    ReportStatement,
};
use crate::{
    AppError, CancellationToken, CaseId, Engine, SignedEntry,
    v10_proofs::{
        CaseCheckpointV1, ReportCitationsV1, V10CheckpointView, V10Citation, V10RowReference,
    },
};
use irmind_domain::{EvidenceHash, ParquetArtifact};

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
        verify_row: impl FnMut(&ParquetArtifact, V10RowReference) -> Result<(), AppError>,
    ) -> Result<Vec<u8>, AppError> {
        if checkpoint.case_id != *id {
            return Err(AppError::InvalidChain(checkpoint.sequence));
        }
        let _lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        let case = self.repo.get_case(id)?;
        let entries = self.audit_log.entries(id)?;
        let view = V10CheckpointView::resolve(&entries, checkpoint)?;
        let findings = self.findings_unlocked(id, view.entries())?;
        let coverage =
            self.resolve_cited_report_coverage(id, view.entries(), &CancellationToken::new())?;
        CitedReportMaterial {
            title: &case.title,
            checkpoint,
            view,
            findings: &findings,
            coverage: &coverage,
        }
        .render(citations, None, language, format, verify_row)
    }
}

pub(super) struct CitedReportMaterial<'a> {
    pub title: &'a str,
    pub checkpoint: &'a CaseCheckpointV1,
    pub view: V10CheckpointView<'a>,
    pub findings: &'a [super::Finding],
    pub coverage: &'a crate::ResolvedReportCoverage,
}

impl CitedReportMaterial<'_> {
    pub(super) fn render(
        &self,
        citations: &ReportCitationsV1,
        analyst: Option<&crate::v10_proofs::ReportAnalystSectionsV1>,
        language: ReportDocumentLanguage,
        format: ReportDocumentFormat,
        mut verify_row: impl FnMut(&ParquetArtifact, V10RowReference) -> Result<(), AppError>,
    ) -> Result<Vec<u8>, AppError> {
        let mut resolved = Vec::with_capacity(citations.0.len());
        for selection in &citations.0 {
            self.view
                .confirmed_finding(selection.confirmation, &selection.finding_id)?;
            let invalid = || AppError::InvalidChain(selection.confirmation.sequence);
            let finding = self
                .findings
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
            verify_row(&self.view.row_artifact(reference)?, reference)?;
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
            case_id: &self.checkpoint.case_id,
            title: self.title,
            confirmed: &confirmed,
            analyst: analyst.map(|sections| sections.0.each_ref().map(String::as_str)),
            limitations: &self.coverage.limitations(),
        }
        .render(language, format)
    }
}
