use super::{
    AppError, CancellationToken, CaseId, CaseLifecycleError, LocalStore, Path, fs, private_dir,
    storage,
};
use std::fs::Metadata;
fn invalid() -> AppError {
    CaseLifecycleError::UnsafeEntry.into()
}
fn checked_metadata(path: &Path) -> Result<Metadata, AppError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| AppError::Storage(format!("cannot inspect case-owned storage: {e}")))?;
    if meta.file_type().is_symlink() {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
    }
    Ok(meta)
}
pub(super) fn directory(path: &Path) -> Result<(), AppError> {
    if !checked_metadata(path)?.is_dir() {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn regular_metadata(path: &Path) -> Result<Metadata, AppError> {
    let meta = checked_metadata(path)?;
    if !meta.is_file() {
        return Err(invalid());
    }
    Ok(meta)
}
fn walk(
    path: &Path,
    depth: usize,
    visited: &mut usize,
    remove: bool,
    cancel: &CancellationToken,
) -> Result<u64, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    if depth > 64 || *visited >= 2_000_000 {
        return Err(CaseLifecycleError::ScanLimit.into());
    }
    *visited += 1;
    if !path.try_exists().map_err(storage)? {
        // Broken links must also be rejected.
        return match fs::symlink_metadata(path) {
            Ok(_) => Err(invalid()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(AppError::Storage(format!(
                "cannot inspect case-owned storage: {e}"
            ))),
        };
    }
    let meta = checked_metadata(path)?;
    if meta.is_file() {
        if remove {
            fs::remove_file(path)
                .map_err(|e| AppError::Storage(format!("cannot remove case-owned file: {e}")))?;
        }
        return Ok(meta.len());
    }
    if !meta.is_dir() {
        return Err(invalid());
    }
    let mut bytes = 0u64;
    for entry in fs::read_dir(path).map_err(storage)? {
        let entry = entry.map_err(storage)?;
        bytes = bytes
            .checked_add(walk(&entry.path(), depth + 1, visited, remove, cancel)?)
            .ok_or(CaseLifecycleError::ScanLimit)?;
    }
    if remove {
        fs::remove_dir(path)
            .map_err(|e| AppError::Storage(format!("cannot remove case-owned directory: {e}")))?;
    }
    Ok(bytes)
}
pub(super) fn case_bytes(
    store: &LocalStore,
    id: &CaseId,
    cancel: &CancellationToken,
) -> Result<u64, AppError> {
    let path = store.parquet.owned_case_path(id);
    if !checked_metadata(path.parent().ok_or(CaseLifecycleError::UnsafeEntry)?)?.is_dir() {
        return Err(invalid());
    }
    let mut visited = 0;
    walk(&path, 0, &mut visited, false, cancel)
}
pub(super) fn cleanup_case_files(
    store: &LocalStore,
    id: &CaseId,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let path = store.parquet.owned_case_path(id);
    let root = path.parent().ok_or(CaseLifecycleError::UnsafeEntry)?;
    if !checked_metadata(root)?.is_dir() {
        return Err(invalid());
    }
    let quarantine = root.join(".deleted");
    if !quarantine.try_exists().map_err(storage)? {
        fs::create_dir(&quarantine).map_err(storage)?;
    }
    if !checked_metadata(&quarantine)?.is_dir() {
        return Err(invalid());
    }
    private_dir(&quarantine).map_err(storage)?;
    let target = quarantine.join(id.as_str());
    if path.try_exists().map_err(storage)? {
        checked_metadata(&path)?;
        if target.try_exists().map_err(storage)? {
            return Err(invalid());
        }
        fs::rename(&path, &target).map_err(storage)?;
        irmind_fs::sync_directory(root).map_err(storage)?;
    } else if fs::symlink_metadata(&path).is_ok() {
        return Err(invalid());
    }
    let mut visited = 0;
    walk(&target, 0, &mut visited, true, cancel)?;
    irmind_fs::sync_directory(&quarantine).map_err(storage)?;
    Ok(())
}
pub(super) fn unlink_blob(root: &Path, hash: &str) -> Result<(), AppError> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CaseLifecycleError::InvalidReceipt.into());
    }
    directory(root)?;
    let path = root.join(hash);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(storage(e)),
        Ok(_) => {}
    }
    regular_metadata(&path)?;
    fs::remove_file(path).map_err(storage)?;
    irmind_fs::sync_directory(root).map_err(storage)
}
