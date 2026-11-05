use irmind_app::AppError;
use irmind_infra::LocalStore;
use std::path::Path;

/// Interactive sessions use precise artifacts; automation keeps its explicit rollout.
pub(super) fn open(root: &Path, interactive: bool) -> Result<LocalStore, AppError> {
    if interactive {
        LocalStore::open_precise(root)
    } else {
        LocalStore::open(root)
    }
}

#[cfg(all(test, feature = "keystore-file", feature = "parser-json"))]
mod tests;
