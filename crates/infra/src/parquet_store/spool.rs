use super::{AppError, CaseId, ParquetStore, fs, storage};
use std::path::Path;

const SPOOL_PREFIX: &str = "irmind-object-";
const MIN_FREE_MARGIN: u64 = 64 * 1024 * 1024;

impl ParquetStore {
    pub(super) fn spool_dir(&self, case_id: &CaseId) -> Result<std::path::PathBuf, AppError> {
        let dir = self.case_dir(case_id)?.join("spool");
        fs::create_dir_all(&dir).map_err(storage)?;
        irmind_fs::private_dir(&dir).map_err(storage)?;
        Ok(dir)
    }

    pub(super) fn create_normalized_spool(
        &self,
        case_id: &CaseId,
    ) -> Result<tempfile::NamedTempFile, AppError> {
        let dir = self.spool_dir(case_id)?;
        let spool = tempfile::Builder::new()
            .prefix("irmind-normalized-")
            .tempfile_in(&dir)
            .map_err(storage)?;
        irmind_fs::private_file(spool.path()).map_err(storage)?;
        Ok(spool)
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
            if name
                .to_string_lossy()
                .strip_prefix(".verify-")
                .is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                })
            {
                let metadata = fs::symlink_metadata(entry.path()).map_err(storage)?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(super::invalid_source());
                }
                fs::remove_dir_all(entry.path()).map_err(storage)?;
                removed += 1;
                continue;
            }
            if ![SPOOL_PREFIX, "irmind-normalized-"]
                .iter()
                .any(|prefix| name.to_string_lossy().starts_with(prefix))
            {
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
        let canonical_root = fs::canonicalize(root.path()).unwrap();
        assert_eq!(
            fs::canonicalize(path.parent().unwrap()).unwrap(),
            canonical_root
                .join("parquet")
                .join(id.as_str())
                .join("spool")
        );
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
    fn normalized_spools_use_the_same_private_directory_and_orphan_recovery() {
        let root = tempfile::tempdir().unwrap();
        let store = ParquetStore::open(root.path()).unwrap();
        let id = case();
        let normalized = store.create_normalized_spool(&id).unwrap();
        assert_eq!(
            normalized.path().parent(),
            Some(store.spool_dir(&id).unwrap().as_path())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(normalized.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(normalized.path().parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        let (file, path) = normalized.keep().unwrap();
        drop(file);
        assert_eq!(store.remove_orphaned_object_spools(&id).unwrap(), 1);
        assert!(!path.exists());
    }

    #[test]
    fn recovery_removes_only_owned_reconstruction_directories() {
        let root = tempfile::tempdir().unwrap();
        let store = ParquetStore::open(root.path()).unwrap();
        let id = case();
        let spool = store.spool_dir(&id).unwrap();
        let orphan = spool.join(".verify-123");
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join("synthetic.json"), b"{}").unwrap();
        let unrelated = spool.join(".verify-not-owned");
        fs::create_dir(&unrelated).unwrap();
        assert_eq!(store.remove_orphaned_object_spools(&id).unwrap(), 1);
        assert!(!orphan.exists());
        assert!(unrelated.exists());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_does_not_follow_reconstruction_directory_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"synthetic").unwrap();
        let store = ParquetStore::open(root.path()).unwrap();
        let id = case();
        let link = store.spool_dir(&id).unwrap().join(".verify-123");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(store.remove_orphaned_object_spools(&id).is_err());
        assert!(outside.path().join("keep").exists());
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
