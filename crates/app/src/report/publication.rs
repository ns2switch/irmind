//! Attended publication and shared verification of exact report bytes.
use super::{
    ReportDocumentFormat, ReportDocumentLanguage, ResolvedReportCoverage,
    cited::CitedReportMaterial,
};
use crate::{
    Actor, AppError, AuditEventKind, AuditOrigin, CancellationToken, Case, CaseId, Engine,
    SignedEntry, SkillCompiler, SkillReceiptVerifier,
    v10_proofs::{
        CaseCheckpointV1, ReportAnalystSectionsV1, ReportCitationsV1, ReportCoverageV2,
        ReportLanguageV1, ReportMediaV1, ReportPublishedV1, V10CheckpointView, V10ProofDescriptor,
        V10ProofFamily, V10RowReference, v10_proof_commitment,
    },
};
use irmind_domain::ParquetArtifact;
use std::collections::BTreeSet;

const RENDERER: &str = "irmind-report-renderer-v1";
const FAMILY: V10ProofFamily = V10ProofFamily::Report;

pub struct ReportPublicationPlan {
    pub checkpoint: CaseCheckpointV1,
    pub citations: ReportCitationsV1,
    pub analyst: Option<ReportAnalystSectionsV1>,
    pub language: ReportDocumentLanguage,
    pub format: ReportDocumentFormat,
}

pub fn report_publication(entry: &SignedEntry) -> Result<ReportPublishedV1, AppError> {
    let invalid = || AppError::InvalidChain(entry.seq);
    let receipt = ReportPublishedV1::decode(&entry.payload).map_err(|_| invalid())?;
    if entry.kind != AuditEventKind::ReportPublishedV1
        || entry.actor != Actor::Analyst
        || entry.origin != "analyst"
        || entry.evidence.is_some()
        || receipt.checkpoint.case_id.as_str() != entry.case_id
        || receipt.checkpoint.sequence >= entry.seq
        || receipt.renderer != RENDERER
        || receipt.reviewed_model_draft.is_some()
    {
        return Err(invalid());
    }
    Ok(receipt)
}

pub fn report_object_keys(receipt: &ReportPublishedV1) -> impl Iterator<Item = (u8, [u8; 32])> {
    [
        (0, Some(receipt.citations)),
        (1, receipt.analyst_sections),
        (2, Some(receipt.coverage)),
        (3, Some(receipt.rendered_sha256)),
    ]
    .into_iter()
    .filter_map(|(kind, digest)| digest.map(|digest| (kind, digest)))
}

impl Engine<'_> {
    pub fn publish_cited_report(
        &self,
        id: &CaseId,
        plan: ReportPublicationPlan,
        cancel: &CancellationToken,
    ) -> Result<ReportPublishedV1, AppError> {
        self.require_attended_analyst("publish signed report")?;
        let _lock = self.repo.lock_case(id)?;
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.audit_log.entries(id)?;
        let view = V10CheckpointView::resolve(&entries, &plan.checkpoint)?;
        if plan.checkpoint.case_id != *id
            || entries.last().map(|entry| entry.seq) != Some(plan.checkpoint.sequence)
        {
            return Err(AppError::Policy(
                "Report preview is stale. Preview the case again before signing.".into(),
            ));
        }
        let coverage = self.resolve_cited_report_coverage(view.entries(), cancel)?;
        let findings = self.findings_unlocked(id, view.entries())?;
        let store = self.large_case_store.as_ref().ok_or_else(unavailable)?;
        let material = CitedReportMaterial {
            title: &case.title,
            checkpoint: &plan.checkpoint,
            view,
            findings: &findings,
            coverage: &coverage,
        };
        let rendered = material.render(
            &plan.citations,
            plan.analyst.as_ref(),
            plan.language,
            plan.format,
            |artifact, row| store.verify_report_row(id, artifact, row, cancel),
        )?;
        let mut objects = vec![(0, plan.citations.encode().map_err(|_| unavailable())?)];
        if let Some(analyst) = &plan.analyst {
            objects.push((1, analyst.encode().map_err(|_| unavailable())?));
        }
        objects.push((2, coverage.proof.encode().map_err(|_| unavailable())?));
        objects.push((3, rendered));
        let descriptors = objects
            .iter()
            .map(|(kind, body)| {
                V10ProofDescriptor::from_body(FAMILY, *kind, body).map_err(|_| unavailable())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let receipt = ReportPublishedV1 {
            checkpoint: plan.checkpoint,
            citations: descriptors[0].hash(),
            reviewed_model_draft: None,
            analyst_sections: descriptors
                .iter()
                .find(|object| object.kind() == 1)
                .map(|object| object.hash()),
            coverage: crate::sha256(&objects[objects.len() - 2].1),
            language: match plan.language {
                ReportDocumentLanguage::English => ReportLanguageV1::English,
                ReportDocumentLanguage::Spanish => ReportLanguageV1::Spanish,
            },
            renderer: RENDERER.into(),
            media: match plan.format {
                ReportDocumentFormat::Markdown => ReportMediaV1::Markdown,
                ReportDocumentFormat::Pdf => ReportMediaV1::Pdf,
            },
            rendered_length: objects.last().ok_or_else(unavailable)?.1.len() as u64,
            rendered_sha256: descriptors.last().ok_or_else(unavailable)?.hash(),
            proof_set: v10_proof_commitment(FAMILY, &descriptors).map_err(|_| unavailable())?,
        };
        let entry = self.signed_entry(
            id,
            AuditOrigin::Analyst,
            AuditEventKind::ReportPublishedV1,
            &receipt.encode().map_err(|_| unavailable())?,
            None,
        )?;
        let bodies = descriptors
            .into_iter()
            .zip(objects.iter().map(|(_, body)| body.as_slice()))
            .collect::<Vec<_>>();
        store.commit_report_proofs(id, &bodies, &entry, cancel)?;
        Ok(receipt)
    }

    pub(crate) fn verify_report_publications(
        &self,
        case: &Case,
        entries: &[SignedEntry],
        skills: &SkillReceiptVerifier,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let store = self.large_case_store.as_ref().ok_or_else(unavailable)?;
        let copied = self
            .evidence_store
            .evidence_hashes(&case.id)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        verify_report_history(
            &case.title,
            entries,
            &copied,
            self.skills
                .as_ref()
                .map(|services| (skills, services.compiler.as_ref())),
            |kind, digest| store.read_report_proof(&case.id, kind, digest, cancel),
            |artifact, row| store.verify_report_row(&case.id, artifact, row, cancel),
            cancel,
        )
        .map(|_| ())
    }
}

/// The caller has authenticated the ledger, branch material and evidence
/// inventory. This function also verifies the exact artifact row and output.
pub fn verify_report_history(
    title: &str,
    entries: &[SignedEntry],
    copied_evidence: &BTreeSet<String>,
    skills: Option<(&SkillReceiptVerifier, &dyn SkillCompiler)>,
    mut read: impl FnMut(u8, [u8; 32]) -> Result<Vec<u8>, AppError>,
    mut verify_row: impl FnMut(&ParquetArtifact, V10RowReference) -> Result<(), AppError>,
    cancel: &CancellationToken,
) -> Result<BTreeSet<(u8, [u8; 32])>, AppError> {
    let mut referenced = BTreeSet::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::ReportPublishedV1)
    {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let receipt = report_publication(entry)?;
        let view = V10CheckpointView::resolve(entries, &receipt.checkpoint)?;
        let coverage = ResolvedReportCoverage::resolve(view.entries(), skills)?;
        let mut known = copied_evidence.clone();
        for evidence in view.entries() {
            if let Some(source) =
                crate::SourceManifestV1::decode_signed(evidence.kind, &evidence.payload)
                    .map_err(|_| AppError::InvalidChain(evidence.seq))?
            {
                known.insert(source.sha256.as_str().into());
            }
        }
        let findings = super::replay_findings(view.entries(), &known)?;
        let material = CitedReportMaterial {
            title,
            checkpoint: &receipt.checkpoint,
            view,
            findings: &findings,
            coverage: &coverage,
        };
        verify_one_report(
            &material,
            &receipt,
            &mut read,
            &mut verify_row,
            &mut referenced,
        )?;
    }
    Ok(referenced)
}

fn verify_one_report(
    material: &CitedReportMaterial<'_>,
    receipt: &ReportPublishedV1,
    read: &mut impl FnMut(u8, [u8; 32]) -> Result<Vec<u8>, AppError>,
    verify_row: &mut impl FnMut(&ParquetArtifact, V10RowReference) -> Result<(), AppError>,
    referenced: &mut BTreeSet<(u8, [u8; 32])>,
) -> Result<(), AppError> {
    let invalid = || AppError::InvalidChain(receipt.checkpoint.sequence);
    let mut proofs = Vec::new();
    let mut object = |kind, hash| {
        let body = read(kind, hash)?;
        let descriptor =
            V10ProofDescriptor::from_body(FAMILY, kind, &body).map_err(|_| invalid())?;
        if descriptor.hash() != hash {
            return Err(invalid());
        }
        proofs.push(descriptor);
        referenced.insert((kind, hash));
        Ok(body)
    };
    let citations =
        ReportCitationsV1::decode(&object(0, receipt.citations)?).map_err(|_| invalid())?;
    let analyst = receipt
        .analyst_sections
        .map(|hash| ReportAnalystSectionsV1::decode(&object(1, hash)?).map_err(|_| invalid()))
        .transpose()?;
    let coverage =
        ReportCoverageV2::decode(&object(2, receipt.coverage)?).map_err(|_| invalid())?;
    if coverage != material.coverage.proof {
        return Err(invalid());
    }
    let body = object(3, receipt.rendered_sha256)?;
    if body.len() as u64 != receipt.rendered_length
        || v10_proof_commitment(FAMILY, &proofs).map_err(|_| invalid())? != receipt.proof_set
    {
        return Err(invalid());
    }
    let rendered = material.render(
        &citations,
        analyst.as_ref(),
        match receipt.language {
            ReportLanguageV1::English => ReportDocumentLanguage::English,
            ReportLanguageV1::Spanish => ReportDocumentLanguage::Spanish,
        },
        match receipt.media {
            ReportMediaV1::Markdown => ReportDocumentFormat::Markdown,
            ReportMediaV1::Pdf => ReportDocumentFormat::Pdf,
        },
        verify_row,
    )?;
    if rendered != body {
        return Err(invalid());
    }
    Ok(())
}

fn unavailable() -> AppError {
    AppError::Policy("Signed report proofs are unavailable or exceed their limits".into())
}
