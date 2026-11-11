//! Reproduce the exact bounded source group recorded by the direct recipe.
use super::{
    AppError, Arc, CancellationToken, CaseId, Inputs, LargeCaseStore, LogParser, ParquetArtifact,
    ParquetArtifactV3, ParquetStore, Path, SourceManifestV2, invalid_source, original_location,
};
use irmind_app::MappedIngestRequest;
use irmind_domain::{MappingProfileV1, SourceRecordSetV1};

impl ParquetStore {
    pub(super) fn rebuild_direct_group(
        &self,
        location: (&CaseId, &Path, &Path),
        artifact: &ParquetArtifactV3,
        inputs: &Inputs,
        seed: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<Vec<ParquetArtifactV3>, AppError> {
        let binding = artifact.bindings().first().ok_or_else(invalid_source)?;
        let profile = inputs
            .profiles
            .get(binding.profile())
            .ok_or_else(invalid_source)?;
        let sources = group_sources(profile, inputs)?;
        let catalog = self
            .mapping_catalog
            .as_ref()
            .ok_or_else(invalid_source)?
            .frozen_for_profile(profile)
            .map_err(irmind_app::source_mapping::MappingError::into_app)?;
        let first = sources.first().ok_or_else(invalid_source)?;
        let selection = catalog
            .decoder_selection(first.0.decoder().id(), first.0.decoder().version())
            .map_err(irmind_app::source_mapping::MappingError::into_app)?;
        let mut selection: Arc<dyn LogParser> = Arc::new(selection);
        if let Some(context) = first.0.time_context() {
            selection = selection
                .with_time_context(&irmind_app::source_mapping::parser_time_context(context)?)?;
        }
        let mut prepared = self.prepare_direct_history(
            location,
            &sources,
            catalog,
            selection.as_ref(),
            seed,
            cancel,
        )?;
        let manifests = sources
            .iter()
            .map(|(_, s)| (*s).clone())
            .collect::<Vec<_>>();
        let bound = prepared.metadata().bind(&manifests)?;
        for set in &bound.inputs {
            if inputs
                .sets
                .get(&set.identity().map_err(|_| invalid_source())?)
                != Some(set)
            {
                return Err(invalid_source());
            }
        }
        if &bound.profile != profile || inputs.runs.get(binding.profile()) != Some(&bound.receipt) {
            return Err(invalid_source());
        }
        prepared.publish(cancel)?;
        prepared.retain_committed();
        Ok(bound.artifacts)
    }

    fn prepare_direct_history(
        &self,
        location: (&CaseId, &Path, &Path),
        sources: &[(&SourceRecordSetV1, &SourceManifestV2)],
        catalog: irmind_app::source_mapping::MappingCatalog,
        selection: &dyn LogParser,
        seed: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<Box<dyn irmind_app::PreparedMappedIngest>, AppError> {
        let (case, root, workspace) = location;
        let alias = crate::parquet_store::TempWorkspace::new(&self.spool_dir(case)?)?;
        let remote = sources.iter().any(|(_, s)| s.source.source.contains("://"));
        let (source_root, paths) = if remote {
            let [(_, source)] = sources else {
                return Err(invalid_source());
            };
            original_location(self, case, root, source)?
        } else {
            let original = if sources.iter().all(|(_, s)| !s.source.copied) {
                root.to_owned()
            } else {
                self.prepare_direct_originals(case, root, &alias.path, sources, cancel)?;
                alias.path.clone()
            };
            (
                original,
                sources
                    .iter()
                    .map(|(_, s)| s.source.source.clone())
                    .collect(),
            )
        };
        let routed =
            remote.then(|| irmind_app::SourceParser::new(selection, &sources[0].1.source.source));
        let parser: &dyn irmind_app::StreamingEventParser = routed
            .as_ref()
            .map_or(selection, |p| p as &dyn irmind_app::StreamingEventParser);
        let fresh = Self::open_mapped(workspace, Arc::new(catalog))?;
        fresh
            .prepare_mapped_ingest(
                MappedIngestRequest {
                    case_id: case,
                    source_root: &source_root,
                    relative_paths: &paths,
                    copy_original: false,
                    parser,
                    committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(seed),
                    limits: crate::parquet_store::partitioning::replay_limits(seed)?,
                },
                cancel,
            )?
            .ok_or_else(invalid_source)
    }

    fn prepare_direct_originals(
        &self,
        case: &CaseId,
        root: &Path,
        destination: &Path,
        sources: &[(&SourceRecordSetV1, &SourceManifestV2)],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        use std::io::{Read as _, Write as _};
        let required = sources
            .iter()
            .try_fold(64 * 1024 * 1024u64, |total, (_, source)| {
                total
                    .checked_add(source.source.size)
                    .and_then(|bytes| bytes.checked_add(source.source.size / 20))
                    .ok_or_else(invalid_source)
            })?;
        if fs4::available_space(destination).map_err(crate::parquet_store::storage)? < required {
            return Err(AppError::Storage(
                "not enough free case storage to reconstruct the direct source group".into(),
            ));
        }
        for (_, source) in sources {
            irmind_domain::SourceReferenceV1::file(&source.source.source)
                .map_err(|_| invalid_source())?;
            let (originals, paths) = original_location(self, case, root, source)?;
            let mut input = Self::open_source(&originals, &paths[0])?;
            let target = destination.join(&source.source.source);
            let parent = target.parent().ok_or_else(invalid_source)?;
            std::fs::create_dir_all(parent).map_err(crate::parquet_store::storage)?;
            irmind_fs::private_dir(parent).map_err(crate::parquet_store::storage)?;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(crate::parquet_store::storage)?;
            irmind_fs::private_file(&target).map_err(crate::parquet_store::storage)?;
            let mut buffer = [0; 16 * 1024];
            loop {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let size = input
                    .read(&mut buffer)
                    .map_err(crate::parquet_store::storage)?;
                if size == 0 {
                    break;
                }
                output
                    .write_all(&buffer[..size])
                    .map_err(crate::parquet_store::storage)?;
            }
        }
        Ok(())
    }
}

fn group_sources<'a>(
    profile: &MappingProfileV1,
    inputs: &'a Inputs,
) -> Result<Vec<(&'a SourceRecordSetV1, &'a SourceManifestV2)>, AppError> {
    let mut sources = profile
        .inputs()
        .iter()
        .map(|reference| {
            let set = inputs
                .sets
                .get(reference.set())
                .ok_or_else(invalid_source)?;
            let source = inputs
                .sources
                .get(set.source())
                .ok_or_else(invalid_source)?;
            Ok((set, source))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    sources.sort_by(|a, b| a.1.source.source.cmp(&b.1.source.source));
    let first = sources.first().ok_or_else(invalid_source)?;
    if sources.iter().any(|(set, _)| {
        set.decoder() != first.0.decoder() || set.time_context() != first.0.time_context()
    }) {
        return Err(invalid_source());
    }
    Ok(sources)
}
