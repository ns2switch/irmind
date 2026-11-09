use super::{
    AppError, CancellationToken, CaseId, Inputs, LargeCaseStore, ParquetArtifact,
    ParquetArtifactV3, ParquetStore, Path, SourceManifestV2, invalid_source,
};
mod direct;
use irmind_app::{LocalBatchRequest, LogParser};
use std::sync::Arc;

impl ParquetStore {
    pub(super) fn rebuild_mapping_source(
        &self,
        location: (&CaseId, &Path, &Path),
        artifact: &ParquetArtifactV3,
        inputs: &Inputs,
        seed: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<Vec<ParquetArtifactV3>, AppError> {
        let (case, root, workspace) = location;
        if artifact.core().builder_version == irmind_domain::COMMON_EVENT_DIRECT_BUILDER {
            return self.rebuild_direct_group(location, artifact, inputs, seed, cancel);
        }
        let binding = artifact.bindings().first().ok_or_else(invalid_source)?;
        let set = inputs
            .sets
            .get(binding.input().set())
            .ok_or_else(invalid_source)?;
        let source = inputs
            .sources
            .get(set.source())
            .ok_or_else(invalid_source)?;
        let profile = inputs
            .profiles
            .get(binding.profile())
            .ok_or_else(invalid_source)?;
        if profile.inputs().len() != 1 {
            return Err(invalid_source());
        }
        let catalog = self.mapping_catalog.as_ref().ok_or_else(|| AppError::Policy(
            "full reconstruction requires the exact locally installed decoder and mapping versions; signature authentication remains available".into()))?
            .frozen_for_profile(profile).map_err(irmind_app::source_mapping::MappingError::into_app)?;
        let selection = catalog
            .decoder_selection(set.decoder().id(), set.decoder().version())
            .map_err(irmind_app::source_mapping::MappingError::into_app)?;
        let mut selection: Arc<dyn LogParser> = Arc::new(selection);
        if let Some(context) = set.time_context() {
            selection = selection
                .with_time_context(&irmind_app::source_mapping::parser_time_context(context)?)?;
        }
        let routed = irmind_app::SourceParser::new(selection.as_ref(), &source.source.source);
        let (originals, paths) = original_location(self, case, root, source)?;
        let fresh = Self::open_mapped(workspace, Arc::new(catalog))?;
        let mut prepared = fresh
            .prepare_local_batch(
                LocalBatchRequest {
                    case_id: case,
                    source_root: &originals,
                    relative_paths: &paths,
                    copy_original: false,
                    parser: &routed,
                    committed_artifacts: seed,
                    limits: super::super::super::partitioning::replay_limits(seed)?,
                },
                cancel,
            )?
            .pop()
            .ok_or_else(invalid_source)?;
        if prepared.manifest.size != source.source.size
            || prepared.manifest.sha256 != source.source.sha256
        {
            return Err(AppError::EvidenceMismatch(
                source.source.sha256.as_str().into(),
            ));
        }
        let bound = prepared
            .mapping
            .take()
            .ok_or_else(invalid_source)?
            .bind(source)?;
        if bound.input() != set
            || bound.profile() != profile
            || inputs.runs.get(binding.profile()) != Some(bound.receipt())
        {
            return Err(invalid_source());
        }
        Ok(bound.into_artifacts())
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
