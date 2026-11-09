use super::{
    AppError, AuditEventKind, AuditOrigin, EvidenceHash, LargeCaseUseCases, ParquetArtifact,
    RejectedSource, Request, invalid_manifest, rejection_events,
};
use crate::PreparedMappedGroup;
use crate::{PreparedMappedIngest, PreparedSource};
use irmind_domain::{MappingProfileRecordV1, SourceManifestV2};
type DirectEvents = (
    Vec<SourceManifestV2>,
    Vec<(AuditOrigin, AuditEventKind, String)>,
    Vec<ParquetArtifact>,
);
pub(super) type Accepted = (String, EvidenceHash, Vec<(String, ParquetArtifact)>);
impl LargeCaseUseCases<'_, '_> {
    pub(super) fn commit_direct(
        &self,
        request: &Request<'_>,
        paths: &[String],
        prepared: &mut dyn PreparedMappedIngest,
        rejected: &[RejectedSource],
    ) -> Result<Vec<Accepted>, AppError> {
        let (sources, events, outputs) =
            self.direct_events(request, paths, prepared.metadata(), rejected)?;
        if request.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        prepared.publish(request.cancel)?;
        for artifact in &outputs {
            self.store
                .verify_artifact(request.id, artifact, request.cancel)?;
        }
        if request.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.engine.audit_batch(request.id, &events)?;
        prepared.retain_committed();
        let pairs = outputs
            .into_iter()
            .map(|a| (a.path().to_owned(), a))
            .collect::<Vec<_>>();
        Ok(sources
            .into_iter()
            .enumerate()
            .map(|(i, source)| {
                (
                    source.source.source,
                    source.source.sha256,
                    if i == 0 { pairs.clone() } else { vec![] },
                )
            })
            .collect())
    }
    fn direct_events(
        &self,
        request: &Request<'_>,
        paths: &[String],
        metadata: &PreparedMappedGroup,
        rejected: &[RejectedSource],
    ) -> Result<DirectEvents, AppError> {
        if !metadata
            .sources
            .iter()
            .map(|s| &s.manifest.source)
            .eq(paths.iter())
        {
            return Err(invalid_manifest());
        }

        let mut sources = Vec::new();
        let mut events = rejection_events(rejected)?;
        for source in &metadata.sources {
            if request
                .selections
                .get(&source.manifest.source)
                .is_some_and(|selection| {
                    selection.timestamp_context.as_deref() != self.parser.timestamp_context()
                })
            {
                return Err(invalid_manifest());
            }
            let temporary = PreparedSource {
                mapping: None,
                manifest: source.manifest.clone(),
                artifacts: vec![],
                records: source.report.accepted,
                format_sample_sha256: source.format_sample_sha256,
                parse_report: source.report.clone(),
            };
            let (kind, payload) =
                self.source_event(&temporary, request.selections.get(&source.manifest.source))?;
            sources.push(SourceManifestV2::decode(&payload).map_err(|_| invalid_manifest())?);
            events.push((AuditOrigin::System, kind, payload));
        }
        let bound = metadata.bind(&sources)?;
        for input in &bound.inputs {
            events.push((
                AuditOrigin::System,
                AuditEventKind::SourceRecordSetV1,
                input.encode().map_err(|_| invalid_manifest())?,
            ));
        }
        let catalog = bound.profile.catalog_identity();
        if !request.known_artifacts.values().any(|a| matches!(a, ParquetArtifact::V3(v) if v.bindings().iter().any(|b| b.catalog() == &catalog))) {
            for snapshot in &bound.snapshots { events.push((AuditOrigin::System, AuditEventKind::MappingProfileV1,
                MappingProfileRecordV1::Snapshot(snapshot.clone()).encode().map_err(|_| invalid_manifest())?)); }
        }
        events.push((
            AuditOrigin::System,
            AuditEventKind::MappingProfileV1,
            MappingProfileRecordV1::Profile(bound.profile)
                .encode()
                .map_err(|_| invalid_manifest())?,
        ));
        self.engine.verify_mapping_events(
            events
                .iter()
                .map(|(_, kind, payload)| (*kind, payload.as_str())),
        )?;
        let mut outputs = Vec::new();
        for artifact in bound.artifacts {
            let artifact = ParquetArtifact::V3(artifact);
            if request.known_artifacts.contains_key(artifact.path()) {
                return Err(invalid_manifest());
            }
            events.push((
                AuditOrigin::System,
                artifact.audit_kind(),
                artifact.encode().map_err(|_| invalid_manifest())?,
            ));
            outputs.push(artifact);
        }
        events.push((
            AuditOrigin::System,
            AuditEventKind::MappingRunV1,
            bound.receipt.encode().map_err(|_| invalid_manifest())?,
        ));
        Ok((sources, events, outputs))
    }
}
