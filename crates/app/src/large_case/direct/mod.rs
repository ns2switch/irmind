//! Atomic direct groups. Rejected candidates never determine physical boundaries.
mod commit;
use super::{
    AppError, AuditEventKind, AuditOrigin, BTreeMap, CancellationToken, CaseId, EvidenceHash,
    LargeCaseUseCases, ParquetArtifact, ParserSelection, Path, SourceManifestV1, invalid_manifest,
};
use crate::mapped_ingest::{MAPPED_GROUP_EXCLUSIONS, MAPPED_GROUP_SOURCES};
use crate::{MappedIngestRequest, RejectedSource};
pub(super) struct Request<'a> {
    pub id: &'a CaseId,
    pub source_root: &'a Path,
    pub ordered: &'a [String],
    pub copy_original: bool,
    pub selections: &'a BTreeMap<String, ParserSelection>,
    pub known_artifacts: &'a mut BTreeMap<String, ParquetArtifact>,
    pub known_sources: &'a BTreeMap<String, SourceManifestV1>,
    pub cancel: &'a CancellationToken,
}
impl LargeCaseUseCases<'_, '_> {
    pub(super) fn try_direct(
        &self,
        request: &mut Request<'_>,
    ) -> Result<Option<Vec<(String, EvidenceHash)>>, AppError> {
        let mut pending = pending_paths(request);
        let mut ingested = Vec::new();
        if pending.is_empty() {
            return Ok(None);
        }
        let mut used_direct = false;
        let mut verified_existing = false;
        while !pending.is_empty() {
            let mut rejected = Vec::new();
            loop {
                if request.cancel.is_cancelled() {
                    self.audit_rejections(request.id, &rejected)?;
                    return Err(AppError::Cancelled);
                }
                let paths = pending
                    .iter()
                    .take(MAPPED_GROUP_SOURCES)
                    .cloned()
                    .collect::<Vec<_>>();
                if paths.is_empty() {
                    self.audit_rejections(request.id, &rejected)?;
                    break;
                }
                let attempt = self.prepare_direct_attempt(request, &paths);
                match attempt {
                    Ok(None) if !used_direct && rejected.is_empty() => return Ok(None),
                    Ok(None) => {
                        self.audit_rejections(request.id, &rejected)?;
                        return Err(AppError::Policy(
                            "direct preparation became unavailable".into(),
                        ));
                    }
                    Ok(Some(mut prepared)) => {
                        let accepted = match self.finish_direct_attempt(
                            request,
                            &paths,
                            prepared.as_mut(),
                            &rejected,
                            (!verified_existing).then_some(&mut ingested),
                        ) {
                            Ok(accepted) => accepted,
                            Err(error) => {
                                drop(prepared);
                                self.audit_rejections(request.id, &rejected)?;
                                return Err(error);
                            }
                        };
                        used_direct = true;
                        verified_existing = true;
                        record_accepted(request, &mut pending, &mut ingested, accepted);
                        break;
                    }
                    Err(AppError::SourceFailure(source)) if !request.cancel.is_cancelled() => {
                        self.verify_existing_once(
                            request,
                            &mut verified_existing,
                            &mut ingested,
                            &rejected,
                        )?;
                        self.exclude_direct_source(
                            request,
                            &paths,
                            source,
                            &mut pending,
                            &mut rejected,
                        )?;
                    }
                    Err(error) => {
                        self.audit_rejections(request.id, &rejected)?;
                        return Err(error);
                    }
                }
            }
        }
        ingested.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Some(ingested))
    }
    fn verify_existing_once(
        &self,
        request: &Request<'_>,
        verified: &mut bool,
        ingested: &mut Vec<(String, EvidenceHash)>,
        rejected: &[RejectedSource],
    ) -> Result<(), AppError> {
        if !*verified {
            if let Err(error) = self.verify_direct_existing(request, ingested) {
                self.audit_rejections(request.id, rejected)?;
                return Err(error);
            }
            *verified = true;
        }
        Ok(())
    }
    fn exclude_direct_source(
        &self,
        request: &Request<'_>,
        paths: &[String],
        source: RejectedSource,
        pending: &mut Vec<String>,
        rejected: &mut Vec<RejectedSource>,
    ) -> Result<(), AppError> {
        if !paths.iter().any(|p| p == source.source()) {
            self.audit_rejections(request.id, rejected)?;
            return Err(invalid_manifest());
        }
        pending.retain(|p| p != source.source());
        rejected.push(source);
        if rejected.len() > MAPPED_GROUP_EXCLUSIONS {
            self.audit_rejections(request.id, rejected)?;
            return Err(AppError::Policy(format!(
                "direct group rejected {} sources; the exclusion limit is 16; group rolled back",
                rejected.len()
            )));
        }
        Ok(())
    }
    fn finish_direct_attempt(
        &self,
        request: &Request<'_>,
        paths: &[String],
        prepared: &mut dyn crate::PreparedMappedIngest,
        rejected: &[RejectedSource],
        existing: Option<&mut Vec<(String, EvidenceHash)>>,
    ) -> Result<Vec<commit::Accepted>, AppError> {
        if let Some(ingested) = existing {
            self.verify_direct_existing(request, ingested)?;
        }
        let actual = paths
            .get(..prepared.metadata().sources.len())
            .filter(|paths| !paths.is_empty())
            .ok_or_else(invalid_manifest)?;
        self.commit_direct(request, actual, prepared, rejected)
    }
    fn prepare_direct_attempt(
        &self,
        request: &Request<'_>,
        paths: &[String],
    ) -> Result<Option<Box<dyn crate::PreparedMappedIngest>>, AppError> {
        self.store.prepare_mapped_ingest(
            MappedIngestRequest {
                case_id: request.id,
                source_root: request.source_root,
                relative_paths: paths,
                copy_original: request.copy_original,
                parser: self.parser,
                committed_artifacts: crate::mapped_ingest::CommittedArtifacts::Indexed(
                    request.known_artifacts,
                ),
                limits: crate::PartitionLimits::default(),
            },
            request.cancel,
        )
    }
    fn verify_direct_existing(
        &self,
        request: &Request<'_>,
        ingested: &mut Vec<(String, EvidenceHash)>,
    ) -> Result<(), AppError> {
        for path in request.ordered {
            if let Some(old) = request.known_sources.get(path) {
                if request.copy_original && !old.copied {
                    return Err(AppError::Policy(
                        "this source was signed without a copy; select a new source path".into(),
                    ));
                }
                self.store
                    .verify_local_source(request.source_root, old, request.cancel)?;
                ingested.push((path.clone(), old.sha256.clone()));
            }
        }
        Ok(())
    }
    fn audit_rejections(&self, id: &CaseId, rejected: &[RejectedSource]) -> Result<(), AppError> {
        let events = rejection_events(rejected)?;
        if !events.is_empty() {
            self.engine.audit_batch(id, &events)?;
        }
        Ok(())
    }
}
fn rejection_events(
    rejected: &[RejectedSource],
) -> Result<Vec<(AuditOrigin, AuditEventKind, String)>, AppError> {
    rejected
        .iter()
        .map(|source| {
            Ok((
                AuditOrigin::System,
                AuditEventKind::ToolError,
                source.audit_payload()?,
            ))
        })
        .collect()
}

fn record_accepted(
    request: &mut Request<'_>,
    pending: &mut Vec<String>,
    ingested: &mut Vec<(String, EvidenceHash)>,
    accepted: Vec<commit::Accepted>,
) {
    let accepted_paths = accepted
        .iter()
        .map(|(path, _, _)| path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for (path, hash, artifacts) in accepted {
        ingested.push((path, hash));
        request.known_artifacts.extend(artifacts);
    }
    pending.retain(|path| !accepted_paths.contains(path));
}

fn pending_paths(request: &Request<'_>) -> Vec<String> {
    request
        .ordered
        .iter()
        .filter(|path| !request.known_sources.contains_key(*path))
        .cloned()
        .collect::<Vec<_>>()
}
