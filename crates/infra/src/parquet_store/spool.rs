use super::{AppError, CaseId, ParquetStore, fs, storage};
use std::path::Path;

const SPOOL_PREFIX: &str = "irmind-object-";
const MIN_FREE_MARGIN: u64 = 64 * 1024 * 1024;

impl ParquetStore {
    fn spool_dir(&self, case_id: &CaseId) -> Result<std::path::PathBuf, AppError> {
        let dir = self.case_dir(case_id)?.join("spool");
        fs::create_dir_all(&dir).map_err(storage)?;
        irmind_fs::private_dir(&dir).map_err(storage)?;
        Ok(dir)
    }

    pub(super) fn create_private_object_spool(
        &self,
        case_id: &CaseId,
        expected_bytes: u64,
    ) -> Result<tempfile::NamedTempFile, AppError> {
        let dir = self.spool_dir(case_id)?;
        let margin = MIN_FREE_MARGIN.max(expected_bytes / 20);
        let required = expected_bytes.checked_add(margin).ok_or_else(|| {
            AppError::Storage("object size exceeds available case storage".into())
        })?;
        if fs4::available_space(&dir).map_err(storage)? < required {
            return Err(AppError::Storage(format!(
                "not enough free space in case spool; need {required} bytes including safety margin"
            )));
        }
        let spool = tempfile::Builder::new()
            .prefix(SPOOL_PREFIX)
            .tempfile_in(&dir)
            .map_err(storage)?;
        irmind_fs::private_file(spool.path()).map_err(storage)?;
        Ok(spool)
    }

    pub(super) fn remove_orphaned_object_spools(
        &self,
        case_id: &CaseId,
    ) -> Result<usize, AppError> {
        let dir = self.spool_dir(case_id)?;
        let mut removed = 0;
        for entry in fs::read_dir(&dir).map_err(storage)? {
            let entry = entry.map_err(storage)?;
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with(SPOOL_PREFIX) {
                continue;
            }
            let file =
                irmind_fs::open_regular_no_follow(&dir, Path::new(&name)).map_err(storage)?;
            drop(file);
            fs::remove_file(entry.path()).map_err(storage)?;
            removed += 1;
        }
        Ok(removed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn case() -> CaseId {
        CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap()
    }

    #[test]
    fn object_spool_is_private_and_removed_on_drop_or_recovery() {
        let root = tempfile::tempdir().unwrap();
        let store = ParquetStore::open(root.path()).unwrap();
        let id = case();
        let spool = store.create_private_object_spool(&id, 128).unwrap();
        let path = spool.path().to_path_buf();
        assert!(path.starts_with(root.path().join("parquet").join(id.as_str()).join("spool")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(spool);
        assert!(!path.exists());

        let spool = store.create_private_object_spool(&id, 128).unwrap();
        let (file, orphan) = spool.keep().unwrap();
        drop(file);
        assert_eq!(store.remove_orphaned_object_spools(&id).unwrap(), 1);
        assert!(!orphan.exists());
    }

    #[test]
    fn insufficient_space_fails_before_creating_a_spool() {
        let root = tempfile::tempdir().unwrap();
        let store = ParquetStore::open(root.path()).unwrap();
        let id = case();
        let error = store
            .create_private_object_spool(&id, u64::MAX)
            .err()
            .unwrap();
        assert!(error.to_string().contains("space") || error.to_string().contains("size"));
        assert_eq!(
            fs::read_dir(store.spool_dir(&id).unwrap()).unwrap().count(),
            0
        );
    }
}
