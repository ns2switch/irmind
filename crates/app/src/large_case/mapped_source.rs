//! Bind the immutable decode result only after acquisition metadata is final.
use super::{AppError, AuditEventKind, AuditOrigin, BTreeMap, ParquetArtifact, invalid_manifest};
use irmind_domain::{MappingProfileRecordV1, SourceManifestV2};

type Event = (AuditOrigin, AuditEventKind, String);
pub(super) struct MappedEvents {
    pub(super) before: Vec<Event>,
    pub(super) after: Vec<Event>,
}

pub(super) fn bind(
    prepared: &mut crate::PreparedSource,
    source: &(AuditEventKind, String),
    known: &BTreeMap<String, ParquetArtifact>,
) -> Result<MappedEvents, AppError> {
    let Some(mapping) = prepared.mapping.take() else {
        return Ok(MappedEvents {
            before: vec![],
            after: vec![],
        });
    };
    if source.0 != AuditEventKind::SourceManifestV2 {
        return Err(invalid_manifest());
    }
    let manifest = SourceManifestV2::decode(&source.1).map_err(|_| invalid_manifest())?;
    let bound = mapping.bind(&manifest)?;
    let mut before = vec![(
        AuditOrigin::System,
        AuditEventKind::SourceRecordSetV1,
        bound.input().encode().map_err(|_| invalid_manifest())?,
    )];
    let catalog = bound.profile().catalog_identity();
    let reused = known.values().any(|a| {
        matches!(a, ParquetArtifact::V3(v)
        if v.bindings().iter().any(|b| b.catalog() == &catalog))
    });
    if !reused {
        for snapshot in bound.snapshots() {
            before.push((
                AuditOrigin::System,
                AuditEventKind::MappingProfileV1,
                MappingProfileRecordV1::Snapshot(snapshot.clone())
                    .encode()
                    .map_err(|_| invalid_manifest())?,
            ));
        }
    }
    before.push((
        AuditOrigin::System,
        AuditEventKind::MappingProfileV1,
        MappingProfileRecordV1::Profile(bound.profile().clone())
            .encode()
            .map_err(|_| invalid_manifest())?,
    ));
    let after = vec![(
        AuditOrigin::System,
        AuditEventKind::MappingRunV1,
        bound.receipt().encode().map_err(|_| invalid_manifest())?,
    )];
    prepared.artifacts = bound
        .into_artifacts()
        .into_iter()
        .map(ParquetArtifact::V3)
        .collect();
    Ok(MappedEvents { before, after })
}
