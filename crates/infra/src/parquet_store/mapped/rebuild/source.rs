use super::{
    AppError, CancellationToken, CaseId, Inputs, LargeCaseStore, ParquetArtifact,
    ParquetArtifactV3, ParquetStore, Path, SourceManifestV2, invalid_source,
};
mod direct;

impl ParquetStore {
    pub(super) fn rebuild_mapping_source(
        &self,
        location: (&CaseId, &Path, &Path),
        artifact: &ParquetArtifactV3,
        inputs: &Inputs,
        seed: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<Vec<ParquetArtifactV3>, AppError> {
        if artifact.core().builder_version != irmind_domain::COMMON_EVENT_DIRECT_BUILDER {
            return Err(AppError::Policy(
                "this Parquet construction recipe is retired; reconstruct with the version that created the case".into(),
            ));
        }
        self.rebuild_direct_group(location, artifact, inputs, seed, cancel)
    }
}
fn original_location(
    store: &ParquetStore,
    case: &CaseId,
    root: &Path,
    source: &SourceManifestV2,
) -> Result<(std::path::PathBuf, Vec<String>), AppError> {
    if source.source.copied {
        Ok((
            store.case_dir(case)?.join("originals"),
            vec![source.source.sha256.as_str().into()],
        ))
    } else if source.source.source.contains("://") {
        Ok((root.to_owned(), vec![source.source.sha256.as_str().into()]))
    } else {
        Ok((root.to_owned(), vec![source.source.source.clone()]))
    }
}
