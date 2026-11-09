use super::{DecodedSourceCommitmentV1, MappingError, MappingManifest};
use crate::AppError;
use irmind_domain::{
    ArtifactPipelineV1, COMMON_EVENT_BUILDER, EvidenceHash, MappingBindingV1, MappingIdentityV1,
    MappingInputRefV1, MappingProfileV1, MappingRunV1, MappingSnapshotV1, ParquetArtifactV2,
    ParquetArtifactV3, SourceManifestV2, SourceRecordSetV1,
};

/// Unsigned physical output. It is not a historical V2 custody envelope.
#[derive(Clone)]
pub struct MappedArtifactProjection {
    physical: ParquetArtifactV2,
    mapping: Option<MappingIdentityV1>,
    rows: u64,
}
impl MappedArtifactProjection {
    pub fn try_new(
        physical: ParquetArtifactV2,
        mapping: Option<MappingIdentityV1>,
        rows: u64,
    ) -> Result<Self, AppError> {
        physical.validate().map_err(|_| invalid())?;
        if rows == 0
            || !physical.schema.is_common()
            || !matches!(
                physical.builder_version.as_str(),
                COMMON_EVENT_BUILDER | irmind_domain::COMMON_EVENT_DIRECT_BUILDER
            )
            || !physical.superseded_hashes.is_empty()
        {
            return Err(invalid());
        }
        Ok(Self {
            physical,
            mapping,
            rows,
        })
    }
    pub const fn physical(&self) -> &ParquetArtifactV2 {
        &self.physical
    }
    pub const fn mapping(&self) -> Option<&MappingIdentityV1> {
        self.mapping.as_ref()
    }
    pub const fn rows(&self) -> u64 {
        self.rows
    }
}

/// Metadata is bound after the exact local/object acquisition manifest is known.
/// No output is eligible for the signed catalog before that binding succeeds.
pub struct PreparedMappingSource {
    input: DecodedSourceCommitmentV1,
    snapshots: Vec<MappingSnapshotV1>,
    projections: Vec<MappedArtifactProjection>,
}
impl PreparedMappingSource {
    pub fn try_new(
        input: DecodedSourceCommitmentV1,
        snapshots: Vec<MappingSnapshotV1>,
        projections: Vec<MappedArtifactProjection>,
    ) -> Result<Self, AppError> {
        if projections.is_empty() || projections.len() > 10_000_000 {
            return Err(invalid());
        }
        validate_snapshots(&snapshots)?;
        Ok(Self {
            input,
            snapshots,
            projections,
        })
    }
    pub fn bind(self, manifest: &SourceManifestV2) -> Result<BoundMappingSource, AppError> {
        let input = self.input.bind_manifest(manifest)?;
        let reference = MappingInputRefV1::from_set(&input).map_err(|_| invalid())?;
        let snapshots = self
            .snapshots
            .iter()
            .map(MappingSnapshotV1::reference)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        let profile =
            MappingProfileV1::try_new(vec![reference.clone()], snapshots).map_err(|_| invalid())?;
        let profile_id = profile.identity().map_err(|_| invalid())?;
        let catalog = profile.catalog_identity();
        let artifacts = self
            .projections
            .into_iter()
            .map(|projection| {
                let binding = MappingBindingV1::new(
                    reference.clone(),
                    profile_id.clone(),
                    catalog.clone(),
                    input.decoder().clone(),
                    projection.mapping,
                );
                let pipeline = ArtifactPipelineV1::mapped(vec![binding], projection.rows)
                    .map_err(|_| invalid())?;
                ParquetArtifactV3::try_new(projection.physical, pipeline).map_err(|_| invalid())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let receipt = MappingRunV1::between(&profile, self.input.routes().to_vec(), &artifacts)
            .map_err(|_| invalid())?;
        Ok(BoundMappingSource {
            input,
            snapshots: self.snapshots,
            profile,
            artifacts,
            receipt,
        })
    }
    pub fn catalog_commitment(&self) -> Result<EvidenceHash, AppError> {
        let snapshots = self
            .snapshots
            .iter()
            .map(MappingSnapshotV1::reference)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        irmind_domain::mapping_catalog_commitment(&snapshots).map_err(|_| invalid())
    }
}

pub struct BoundMappingSource {
    input: SourceRecordSetV1,
    snapshots: Vec<MappingSnapshotV1>,
    profile: MappingProfileV1,
    artifacts: Vec<ParquetArtifactV3>,
    receipt: MappingRunV1,
}
impl BoundMappingSource {
    pub const fn input(&self) -> &SourceRecordSetV1 {
        &self.input
    }
    pub fn snapshots(&self) -> &[MappingSnapshotV1] {
        &self.snapshots
    }
    pub const fn profile(&self) -> &MappingProfileV1 {
        &self.profile
    }
    pub fn artifacts(&self) -> &[ParquetArtifactV3] {
        &self.artifacts
    }
    pub const fn receipt(&self) -> &MappingRunV1 {
        &self.receipt
    }
    pub fn into_artifacts(self) -> Vec<ParquetArtifactV3> {
        self.artifacts
    }
}
fn validate_snapshots(snapshots: &[MappingSnapshotV1]) -> Result<(), AppError> {
    if snapshots.len() > 64
        || !snapshots
            .windows(2)
            .all(|s| s[0].mapping().id() < s[1].mapping().id())
    {
        return Err(invalid());
    }
    for snapshot in snapshots {
        MappingManifest::from_snapshot(snapshot).map_err(MappingError::into_app)?;
    }
    Ok(())
}
fn invalid() -> AppError {
    MappingError::InvalidOutput.into_app()
}
