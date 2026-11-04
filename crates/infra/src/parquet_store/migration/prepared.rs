use super::{
    AppError, BTreeSet, CancellationToken, CaseId, ParquetArtifactV2, ParquetMigrationV1,
    ParquetStore, Path, PathBuf, PreparedArtifactMigration, TempWorkspace, invalid_source, storage,
};
use irmind_fs::sync_directory;

pub(super) struct Prepared {
    target: PathBuf,
    workspace: TempWorkspace,
    artifacts: Vec<ParquetArtifactV2>,
    record: ParquetMigrationV1,
    published: Vec<PathBuf>,
    retained: bool,
}

impl Prepared {
    pub(super) fn new(
        target: PathBuf,
        workspace: TempWorkspace,
        artifacts: Vec<ParquetArtifactV2>,
        record: ParquetMigrationV1,
    ) -> Self {
        Self {
            target,
            workspace,
            artifacts,
            record,
            published: Vec::new(),
            retained: false,
        }
    }
}

impl PreparedArtifactMigration for Prepared {
    fn artifacts(&self) -> &[ParquetArtifactV2] {
        &self.artifacts
    }
    fn record(&self) -> &ParquetMigrationV1 {
        &self.record
    }
    fn publish(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        if !self.published.is_empty() || self.retained {
            return Err(invalid_source());
        }
        let id = self.target.file_name().ok_or_else(invalid_source)?;
        let source_case = self.workspace.path.join("parquet").join(id);
        let dirs = self
            .artifacts
            .iter()
            .map(|a| {
                Path::new(&a.path)
                    .parent()
                    .map(Path::to_owned)
                    .ok_or_else(invalid_source)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        for relative in dirs {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let destination = self.target.join(&relative);
            let parent = destination.parent().ok_or_else(invalid_source)?;
            std::fs::create_dir_all(parent).map_err(storage)?;
            irmind_fs::private_dir(parent).map_err(storage)?;
            if destination.try_exists().map_err(storage)? {
                return Err(invalid_source());
            }
            std::fs::rename(source_case.join(&relative), &destination).map_err(storage)?;
            self.published.push(destination.clone());
            sync_published(&destination, &self.target)?;
        }
        Ok(())
    }
    fn retain_committed(&mut self) {
        self.retained = true;
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.retained {
            for dir in &self.published {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
}

pub(super) fn namespace(
    store: &ParquetStore,
    case: &CaseId,
    artifacts: &mut [ParquetArtifactV2],
    generation: &str,
) -> Result<(), AppError> {
    let root = store.case_dir(case)?;
    for artifact in artifacts {
        let old = Path::new(&artifact.path);
        let parent = old.parent().ok_or_else(invalid_source)?;
        let leaf = old.file_name().ok_or_else(invalid_source)?;
        let relative = parent.join(format!("migration-{generation}")).join(leaf);
        let directory = root.join(relative.parent().ok_or_else(invalid_source)?);
        std::fs::create_dir_all(&directory).map_err(storage)?;
        irmind_fs::private_dir(&directory).map_err(storage)?;
        std::fs::rename(root.join(old), root.join(&relative)).map_err(storage)?;
        artifact.path = relative
            .to_str()
            .ok_or_else(invalid_source)?
            .replace('\\', "/");
        artifact.validate().map_err(|_| invalid_source())?;
    }
    Ok(())
}

fn sync_published(directory: &Path, case_root: &Path) -> Result<(), AppError> {
    let mut current = directory;
    loop {
        if !current.starts_with(case_root) {
            return Err(invalid_source());
        }
        sync_directory(current).map_err(storage)?;
        if current == case_root {
            return Ok(());
        }
        current = current.parent().ok_or_else(invalid_source)?;
    }
}
