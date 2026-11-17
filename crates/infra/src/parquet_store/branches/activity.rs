//! A separate gate from both short repository transactions and deletion sessions.
use super::{AppError, CaseId, ParquetStore, fs};
use fs4::fs_std::FileExt;

struct ActivityLease(fs::File);
impl irmind_app::CaseLock for ActivityLease {}
impl Drop for ActivityLease {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}
impl ParquetStore {
    pub(super) fn plan_gate(
        &self,
        case: &CaseId,
        shared: bool,
    ) -> Result<Box<dyn irmind_app::CaseLock>, AppError> {
        let unavailable = || {
            AppError::Storage("Subagent coordination lock is unavailable; check the local data directory and filesystem locking support".into())
        };
        let directory = self.root.parent().ok_or_else(unavailable)?.join("locks");
        fs::create_dir_all(&directory).map_err(|_| unavailable())?;
        let metadata = fs::symlink_metadata(&directory).map_err(|_| unavailable())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(unavailable());
        }
        irmind_fs::private_dir(&directory).map_err(|_| unavailable())?;
        let path = directory.join(format!("{}.subagent-plan", case.as_str()));
        if fs::symlink_metadata(&path)
            .is_ok_and(|meta| meta.file_type().is_symlink() || !meta.is_file())
        {
            return Err(unavailable());
        }
        let mut options = fs::OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                irmind_fs::open_regular_no_follow(
                    &directory,
                    std::path::Path::new(path.file_name().ok_or_else(unavailable)?),
                )
                .map_err(|_| unavailable())?
            }
            Err(_) => return Err(unavailable()),
        };
        irmind_fs::private_file(&path).map_err(|_| unavailable())?;
        if !irmind_fs::regular_file_has_single_link(&file).map_err(|_| unavailable())? {
            return Err(unavailable());
        }
        let acquired = if shared {
            FileExt::try_lock_shared(&file)
        } else {
            FileExt::try_lock_exclusive(&file)
        }
        .map_err(|_| unavailable())?;
        if !acquired {
            return Err(AppError::Policy("Subagent plan is active or being recovered in another session. Finish or cancel it in its owning session, then retry; recovery cannot force the lock".into()));
        }
        Ok(Box::new(ActivityLease(file)))
    }
}
