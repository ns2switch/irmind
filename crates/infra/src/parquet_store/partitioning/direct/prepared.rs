use super::{
    AppError, CancellationToken, ParquetStore, PreparedMappedGroup, PreparedMappedIngest,
    invalid_source,
};
use crate::parquet_store::{PathBuf, StagedArtifact, storage};
use irmind_app::source_mapping::{MappedArtifactProjection, MappingCatalog};
use irmind_domain::ParquetArtifact;

pub(super) fn projections(
    catalog: &MappingCatalog,
    staged: &[StagedArtifact],
) -> Result<Vec<MappedArtifactProjection>, AppError> {
    let routes = crate::parquet_store::mapped::projection_routes_for_direct(catalog)?;
    staged
        .iter()
        .map(|output| {
            let ParquetArtifact::V2(core) = &output.manifest else {
                return Err(invalid_source());
            };
            let route = crate::parquet_store::mapped::route_from_path(&core.path)?
                .ok_or_else(invalid_source)?;
            let mapping = routes
                .iter()
                .find(|(_, token)| token.as_str() == route)
                .map(|(id, _)| id.clone())
                .ok_or_else(invalid_source)?;
            MappedArtifactProjection::try_new(
                core.clone(),
                mapping,
                output.rows.ok_or_else(invalid_source)?,
            )
        })
        .collect()
}
pub(super) struct Prepared {
    root: PathBuf,
    source_root: PathBuf,
    metadata: PreparedMappedGroup,
    staged: Vec<StagedArtifact>,
    published: Vec<PathBuf>,
    copies: bool,
    retained: bool,
    profile: Option<std::sync::Arc<crate::parquet_store::ParquetProfile>>,
}
impl Prepared {
    pub(super) fn new(
        root: PathBuf,
        source_root: PathBuf,
        metadata: PreparedMappedGroup,
        staged: Vec<StagedArtifact>,
        copies: bool,
        profile: Option<std::sync::Arc<crate::parquet_store::ParquetProfile>>,
    ) -> Self {
        Self {
            root,
            source_root,
            metadata,
            staged,
            published: Vec::new(),
            copies,
            retained: false,
            profile,
        }
    }
}
impl PreparedMappedIngest for Prepared {
    fn metadata(&self) -> &PreparedMappedGroup {
        &self.metadata
    }
    fn publish(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        let profile = self.profile.clone();
        let _publish = profile
            .as_ref()
            .map(|p| p.measure(crate::parquet_store::PartitionPhase::Publish));
        if self.retained || !self.published.is_empty() {
            return Err(invalid_source());
        }
        for output in &self.staged {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let target = self.root.join(output.manifest.path());
            if target.try_exists().map_err(storage)? {
                return Err(invalid_source());
            }
            irmind_fs::durable_rename(&output.temporary, &target).map_err(storage)?;
            self.published.push(target.clone());
            irmind_fs::private_file(&target).map_err(storage)?;
        }
        if self.copies {
            self.publish_copies(cancel)?;
        }
        Ok(())
    }
    fn retain_committed(&mut self) {
        self.retained = true;
    }
}
impl Prepared {
    fn publish_copies(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        let case = irmind_domain::CaseId::parse(
            self.root
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(invalid_source)?,
        )
        .map_err(|_| invalid_source())?;
        let store = ParquetStore::open(
            self.root
                .parent()
                .and_then(|p| p.parent())
                .ok_or_else(invalid_source)?,
        )?;
        for input in &self.metadata.sources {
            let mut source = ParquetStore::open_source(&self.source_root, &input.manifest.source)?;
            let copy = self
                .root
                .join("originals")
                .join(input.manifest.sha256.as_str());
            let existed = copy.try_exists().map_err(storage)?;
            if !existed {
                self.published.push(copy);
            }
            store.copy_source(&case, &mut source, &input.manifest.sha256, cancel)?;
        }
        Ok(())
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.retained {
            for path in &self.published {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
