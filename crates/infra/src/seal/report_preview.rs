//! Prepare an unsigned report preview from authenticated, confirmed case rows.
use super::{
    AppError, CancellationToken, CaseId, LocalStore, Path, parquet_frame::locate_v10_artifact_rows,
    storage, storage_reason,
};
use irmind_app::{
    Engine, EntityDetails, ReportDocumentFormat, ReportDocumentLanguage, ReportPublicationPlan,
    SignedEntry, artifact_catalog,
    v10_proofs::{
        CaseCheckpointV1, ReportCitationsV1, V10ArtifactReference, V10AuditReference, V10Citation,
        V10FindingCitations, V10RowReference, V10SourceReference,
    },
};
use irmind_domain::{ArtifactSchemaV2, AuditEventKind, ParquetArtifact, SourceManifestV2};
use std::collections::{BTreeMap, BTreeSet};

pub struct CitedReportPreview {
    pub markdown: String,
    pub omitted_findings: usize,
}

impl LocalStore {
    pub fn preview_cited_report(
        &self,
        engine: &Engine<'_>,
        case: &CaseId,
        language: ReportDocumentLanguage,
        cancel: &CancellationToken,
    ) -> Result<CitedReportPreview, AppError> {
        let (checkpoint, citations, confirmed_count) =
            self.report_coordinates(engine, case, cancel)?;
        let included = citations.0.len();
        let rendered = engine.render_cited_findings(
            case,
            &checkpoint,
            &citations,
            language,
            ReportDocumentFormat::Markdown,
            |artifact, row| {
                irmind_app::LargeCaseStore::verify_report_row(self, case, artifact, row, cancel)
            },
        )?;
        Ok(CitedReportPreview {
            markdown: String::from_utf8(rendered).map_err(storage)?,
            omitted_findings: confirmed_count - included,
        })
    }

    pub fn plan_cited_report(
        &self,
        engine: &Engine<'_>,
        case: &CaseId,
        language: ReportDocumentLanguage,
        format: ReportDocumentFormat,
        cancel: &CancellationToken,
    ) -> Result<ReportPublicationPlan, AppError> {
        let (checkpoint, citations, _) = self.report_coordinates(engine, case, cancel)?;
        Ok(ReportPublicationPlan {
            checkpoint,
            citations,
            analyst: None,
            language,
            format,
        })
    }

    fn report_coordinates(
        &self,
        engine: &Engine<'_>,
        case: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<(CaseCheckpointV1, ReportCitationsV1, usize), AppError> {
        let (entries, findings) = engine.cited_report_inputs(case, cancel)?;
        let recent = entries.last().ok_or(AppError::InvalidChain(0))?;
        let checkpoint = CaseCheckpointV1 {
            case_id: case.clone(),
            sequence: recent.seq,
            entry_hash: recent.hash,
        };
        let references = PreviewReferences::from_entries(&entries)?;
        let mut wanted = BTreeMap::<String, BTreeSet<u64>>::new();
        let mut row_findings = Vec::new();
        let confirmed = findings.iter().filter(|finding| finding.confirmed);
        let confirmed_count = confirmed.clone().count();
        for finding in confirmed {
            let Some(EntityDetails::Timeline {
                at,
                record_index: Some(record),
                ..
            }) = &finding.details
            else {
                continue;
            };
            if references.source(&finding.evidence_hash).is_none() {
                continue;
            }
            let record = *record as u64;
            wanted
                .entry(finding.evidence_hash.clone())
                .or_default()
                .insert(record);
            row_findings.push((at, finding, record));
        }
        row_findings.sort_unstable_by(|(time, finding, _), (other_time, other, _)| {
            (time, &finding.id).cmp(&(other_time, &other.id))
        });
        let rows = self.find_report_rows(case, &entries, &references, &wanted, cancel)?;
        let citations = row_findings
            .into_iter()
            .filter_map(|(_, finding, record)| {
                Some(V10FindingCitations {
                    finding_id: finding.id.clone(),
                    confirmation: *references.confirmations.get(finding.id.as_str())?,
                    citations: vec![V10Citation::Row(
                        *rows.get(&finding.evidence_hash)?.get(&record)?.as_ref()?,
                    )],
                })
            })
            .collect::<Vec<_>>();
        Ok((checkpoint, ReportCitationsV1(citations), confirmed_count))
    }

    fn find_report_rows(
        &self,
        case: &CaseId,
        entries: &[SignedEntry],
        references: &PreviewReferences<'_>,
        wanted: &BTreeMap<String, BTreeSet<u64>>,
        cancel: &CancellationToken,
    ) -> Result<ReportRows, AppError> {
        let mut result = ReportRows::new();
        let root = self.parquet.owned_case_path(case);
        for artifact in artifact_catalog(entries)?.active {
            let ParquetArtifact::V3(envelope) = &artifact;
            if envelope.core().schema != ArtifactSchemaV2::CommonEvents
                || !artifact
                    .source_hashes()
                    .iter()
                    .any(|hash| wanted.contains_key(hash.as_str()))
            {
                continue;
            }
            let signed = *references
                .artifacts
                .get(artifact.path())
                .ok_or_else(invalid)?;
            let file = irmind_fs::open_regular_no_follow(&root, Path::new(artifact.path()))
                .map_err(storage)?;
            locate_v10_artifact_rows(
                file,
                &artifact,
                wanted,
                cancel,
                |hash, record, physical_row| {
                    let source = references.source(hash).ok_or_else(invalid)?;
                    let row = V10RowReference {
                        source,
                        record,
                        artifact: signed,
                        physical_row,
                    };
                    result
                        .entry(hash.into())
                        .or_default()
                        .entry(record)
                        .and_modify(|prior| *prior = None)
                        .or_insert(Some(row));
                    Ok(())
                },
            )?;
        }
        Ok(result)
    }
}

type ReportRows = BTreeMap<String, BTreeMap<u64, Option<V10RowReference>>>;

#[derive(Default)]
struct PreviewReferences<'a> {
    confirmations: BTreeMap<&'a str, V10AuditReference>,
    sources: BTreeMap<String, Option<V10SourceReference>>,
    artifacts: BTreeMap<String, V10ArtifactReference>,
}

impl<'a> PreviewReferences<'a> {
    fn from_entries(entries: &'a [SignedEntry]) -> Result<Self, AppError> {
        let mut references = Self::default();
        for entry in entries {
            let signed = V10AuditReference {
                sequence: entry.seq,
                entry_sha256: entry.hash,
            };
            match entry.kind {
                AuditEventKind::FindingConfirmed => {
                    references.confirmations.insert(&entry.payload, signed);
                }
                AuditEventKind::SourceManifestV2 => {
                    let manifest = SourceManifestV2::decode(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    let hash = manifest.source.sha256.as_str();
                    let source = V10SourceReference {
                        manifest: signed,
                        evidence_sha256: digest(hash)?,
                    };
                    references
                        .sources
                        .entry(hash.into())
                        .and_modify(|previous| *previous = None)
                        .or_insert(Some(source));
                }
                AuditEventKind::ParquetArtifactV3 => {
                    let artifact = ParquetArtifact::decode(entry.kind, &entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    references.artifacts.insert(
                        artifact.path().into(),
                        V10ArtifactReference {
                            entry: signed,
                            artifact_sha256: digest(artifact.sha256().as_str())?,
                        },
                    );
                }
                _ => {}
            }
        }
        Ok(references)
    }

    fn source(&self, hash: &str) -> Option<V10SourceReference> {
        self.sources.get(hash).copied().flatten()
    }
}

fn digest(hex: &str) -> Result<[u8; 32], AppError> {
    let mut bytes = [0; 32];
    ::hex::decode_to_slice(hex, &mut bytes).map_err(storage)?;
    Ok(bytes)
}

fn invalid() -> AppError {
    storage_reason("report citation does not resolve to an authenticated case row")
}
