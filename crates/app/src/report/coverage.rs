use super::ReportLimitation;
use crate::{
    AppError, AuditEventKind, CancellationToken, CaseId, Engine, SignedEntry, SkillCompiler,
    SkillReceiptVerifier,
    source_queries::SourceQueryResultV1,
    v10_proofs::{
        ReportCoverageV2, ReportSkillLoad, ResolvedReportSkillGap, SigmaProofRead, SigmaV3Notice,
        V10AuditReference, V10SourceAvailability, V10SourceReference,
    },
};
use irmind_domain::{EvidenceHash, SourceManifestV2};
use std::collections::BTreeSet;

pub struct ResolvedReportCoverage {
    pub proof: ReportCoverageV2,
    unknown_sources: Vec<String>,
    skill_gaps: Vec<ResolvedReportSkillGap>,
    query_limits: Vec<EvidenceHash>,
    partial_sigma: Vec<SigmaV3Notice>,
    folder: crate::ingest_outcome::FileOutcomeReview,
}

impl ResolvedReportCoverage {
    /// Collect coverage from the authenticated report prefix. The skill replay
    /// has already validated its admission, catalog proofs and branch chunks.
    pub fn resolve(
        entries: &[SignedEntry],
        skills: Option<(&SkillReceiptVerifier, &dyn SkillCompiler)>,
        mut read_sigma: impl FnMut(u8, [u8; 32]) -> Result<SigmaProofRead, AppError>,
    ) -> Result<Self, AppError> {
        let mut proof = ReportCoverageV2::default();
        let mut captures = BTreeSet::new();
        let mut query_limits = Vec::new();
        let mut partial_sigma = Vec::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SigmaRunV2)
        {
            let run = crate::v10_proofs::sigma_execution(entry)?;
            if run.status != crate::v10_proofs::SigmaRunStatusV1::Complete {
                proof.partial_sigma_runs.push(audit_reference(entry));
                partial_sigma.push(SigmaV3Notice::resolve(entry, &mut read_sigma)?);
            }
        }
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceQueryResultV1)
        {
            let result = SourceQueryResultV1::decode(entry.payload.as_bytes())?;
            captures.insert(result.capture_identity().0.to_owned());
            if result.limit_notice().is_some() {
                proof.query_limits.push(audit_reference(entry));
                query_limits.push(EvidenceHash::from_bytes(entry.hash));
            }
        }
        let mut available_parsers = BTreeSet::new();
        let mut unknown_sources = Vec::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        {
            let manifest = SourceManifestV2::decode(&entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            available_parsers.insert(manifest.parser_id);
            let source = manifest.source;
            if !source.copied && !captures.contains(source.sha256.as_str()) {
                let mut hash = [0; 32];
                hex::decode_to_slice(source.sha256.as_str(), &mut hash)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                proof.unavailable_sources.push((
                    V10SourceReference {
                        manifest: audit_reference(entry),
                        evidence_sha256: hash,
                    },
                    V10SourceAvailability::Unknown,
                ));
                unknown_sources.push(source.source);
            }
        }

        let skill_gaps = if let Some((replay, compiler)) = skills {
            let through = entries.last().map_or(0, |entry| entry.seq);
            replay.resolve_report_loads(compiler, through, &available_parsers)?
        } else {
            Vec::new()
        };
        for gap in &skill_gaps {
            if let ReportSkillLoad::Main(load) = gap.load {
                proof.skill_gaps.push((load, gap.index));
            } else if let Some(reference) = gap.delegated_reference() {
                proof.delegated_skill_gaps.push(reference);
            }
        }
        Ok(Self {
            proof,
            unknown_sources,
            skill_gaps,
            query_limits,
            partial_sigma,
            folder: crate::ingest_outcome::FileOutcomeReview::read(entries)?,
        })
    }

    pub(super) fn limitations(&self) -> Vec<ReportLimitation<'_>> {
        self.unknown_sources
            .iter()
            .map(|source| ReportLimitation::SourceAvailabilityUnknown(source))
            .chain(
                self.folder
                    .limitations
                    .iter()
                    .map(ReportLimitation::FolderOutcome),
            )
            .chain(self.skill_gaps.iter().map(|gap| match &gap.load {
                ReportSkillLoad::Main(_) => ReportLimitation::SkillCoverage {
                    skill: &gap.skill,
                    gap: &gap.text,
                },
                ReportSkillLoad::Delegated { task_id, .. } => {
                    ReportLimitation::DelegatedSkillCoverage {
                        skill: &gap.skill,
                        gap: &gap.text,
                        task_id,
                    }
                }
            }))
            .chain(
                self.query_limits
                    .iter()
                    .map(|receipt| ReportLimitation::QueryLimit { receipt }),
            )
            .chain(
                self.partial_sigma
                    .iter()
                    .map(ReportLimitation::SigmaSourceClasses),
            )
            .collect()
    }
}

pub(crate) fn audit_reference(entry: &SignedEntry) -> V10AuditReference {
    V10AuditReference {
        sequence: entry.seq,
        entry_sha256: entry.hash,
    }
}

impl Engine<'_> {
    pub fn report_coverage(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<ReportCoverageV2, AppError> {
        let _lock = self.repo.lock_case(id)?;
        self.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.audit_log.entries(id)?;
        Ok(self
            .resolve_cited_report_coverage(id, &entries, cancel)?
            .proof)
    }

    pub(super) fn resolve_cited_report_coverage(
        &self,
        id: &CaseId,
        entries: &[SignedEntry],
        cancel: &CancellationToken,
    ) -> Result<ResolvedReportCoverage, AppError> {
        let checked = self.checked_skill_receipts(entries, cancel, true)?;
        ResolvedReportCoverage::resolve(
            entries,
            self.skills
                .as_ref()
                .map(|services| (&checked, services.compiler.as_ref())),
            |kind, digest| self.read_sigma_notice_proof(id, kind, digest, cancel),
        )
    }
}
