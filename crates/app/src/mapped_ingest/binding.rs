use super::MappedSourceAcquisition;
use crate::{
    AppError,
    source_mapping::{MappedArtifactProjection, MappingManifest},
};
use irmind_domain::{
    ArtifactPipelineV1, MappingBindingV1, MappingInputRefV1, MappingProfileV1, MappingRunV1,
    MappingSnapshotV1, ParquetArtifactV3, SourceManifestV2, SourceRecordSetV1,
};

#[derive(Clone)]
pub struct PreparedMappedGroup {
    pub sources: Vec<MappedSourceAcquisition>,
    pub snapshots: Vec<MappingSnapshotV1>,
    pub projections: Vec<MappedArtifactProjection>,
}
pub struct BoundMappedGroup {
    pub inputs: Vec<SourceRecordSetV1>,
    pub snapshots: Vec<MappingSnapshotV1>,
    pub profile: MappingProfileV1,
    pub artifacts: Vec<ParquetArtifactV3>,
    pub receipt: MappingRunV1,
}
impl PreparedMappedGroup {
    pub fn bind(&self, manifests: &[SourceManifestV2]) -> Result<BoundMappedGroup, AppError> {
        if self.sources.is_empty()
            || self.sources.len() > super::MAPPED_GROUP_SOURCES
            || manifests.len() != self.sources.len()
            || self.projections.is_empty()
        {
            return Err(bad());
        }
        let mut inputs = self
            .sources
            .iter()
            .zip(manifests)
            .map(|(s, m)| s.decoded.bind_manifest(m))
            .collect::<Result<Vec<_>, _>>()?;
        inputs.sort_by(|a, b| a.source().cmp(b.source()));
        let references = inputs
            .iter()
            .map(MappingInputRefV1::from_set)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| bad())?;
        for snapshot in &self.snapshots {
            MappingManifest::from_snapshot(snapshot)
                .map_err(crate::source_mapping::MappingError::into_app)?;
        }
        let snapshots = self
            .snapshots
            .iter()
            .map(MappingSnapshotV1::reference)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| bad())?;
        let profile = MappingProfileV1::try_new(references, snapshots).map_err(|_| bad())?;
        let artifacts = self.bind_artifacts(&inputs, &profile)?;
        let mut routes = self
            .sources
            .iter()
            .flat_map(|s| s.decoded.routes().iter().cloned())
            .collect::<Vec<_>>();
        routes.sort_by(|a, b| (a.source(), a.mapping()).cmp(&(b.source(), b.mapping())));
        let receipt = MappingRunV1::between(&profile, routes, &artifacts).map_err(|_| bad())?;
        Ok(BoundMappedGroup {
            inputs,
            snapshots: self.snapshots.clone(),
            profile,
            artifacts,
            receipt,
        })
    }
    fn bind_artifacts(
        &self,
        inputs: &[SourceRecordSetV1],
        profile: &MappingProfileV1,
    ) -> Result<Vec<ParquetArtifactV3>, AppError> {
        let profile_id = profile.identity().map_err(|_| bad())?;
        self.projections
            .iter()
            .map(|output| {
                let mut bindings = Vec::new();
                for hash in &output.physical().source_hashes {
                    let input = inputs.iter().find(|s| s.source() == hash).ok_or_else(bad)?;
                    bindings.push(MappingBindingV1::new(
                        MappingInputRefV1::from_set(input).map_err(|_| bad())?,
                        profile_id.clone(),
                        profile.catalog_identity(),
                        input.decoder().clone(),
                        output.mapping().cloned(),
                    ));
                }
                let pipeline =
                    ArtifactPipelineV1::mapped(bindings, output.rows()).map_err(|_| bad())?;
                ParquetArtifactV3::try_new(output.physical().clone(), pipeline).map_err(|_| bad())
            })
            .collect()
    }
}
fn bad() -> AppError {
    AppError::Policy("invalid direct mapped group".into())
}
