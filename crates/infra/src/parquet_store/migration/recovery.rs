use super::{
    AppError, CaseId, EvidenceHash, ParquetArtifact, ParquetStore, Path, PathBuf, invalid_source,
    storage,
};

impl ParquetStore {
    /// Only unsigned migration directories are disposable. Historical signed
    /// generations remain protected even after they leave the active catalog.
    pub(crate) fn remove_orphaned_migrations(
        &self,
        case: &CaseId,
        signed: &[ParquetArtifact],
    ) -> Result<usize, AppError> {
        let root = self.case_dir(case)?;
        let mut pending = vec![(PathBuf::new(), 0usize)];
        let mut removed = 0;
        let mut seen = 0usize;
        while let Some((relative, depth)) = pending.pop() {
            if depth > 6 {
                return Err(invalid_source());
            }
            for entry in std::fs::read_dir(root.join(&relative)).map_err(storage)? {
                seen += 1;
                if seen > 1_000_000 {
                    return Err(invalid_source());
                }
                let entry = entry.map_err(storage)?;
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(invalid_source)?;
                if depth == 0 && !name.starts_with("date=") {
                    continue;
                }
                let metadata = std::fs::symlink_metadata(entry.path()).map_err(storage)?;
                if metadata.file_type().is_symlink() {
                    return Err(invalid_source());
                }
                if !metadata.is_dir() {
                    continue;
                }
                let path = relative.join(name);
                if let Some(hash) = name.strip_prefix("migration-") {
                    EvidenceHash::parse(hash).map_err(|_| invalid_source())?;
                    if !signed
                        .iter()
                        .any(|a| Path::new(a.path()).starts_with(&path))
                    {
                        std::fs::remove_dir_all(entry.path()).map_err(storage)?;
                        irmind_fs::sync_directory(&root.join(&relative)).map_err(storage)?;
                        removed += 1;
                    }
                } else {
                    pending.push((path, depth + 1));
                }
            }
        }
        Ok(removed)
    }
}
