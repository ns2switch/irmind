use irmind_app::AppError;
use irmind_infra::LocalStore;
use std::path::Path;

/// All presentations write precise artifacts and retain compatible V1 reads.
pub(super) fn open(root: &Path) -> Result<LocalStore, AppError> {
    LocalStore::open_precise(root)
}

#[cfg(all(test, feature = "keystore-file", feature = "parser-json"))]
mod tests;
