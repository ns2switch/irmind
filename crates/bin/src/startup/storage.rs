use irmind_app::AppError;
use irmind_infra::LocalStore;
use std::path::Path;

/// All presentations write precise artifacts and retain compatible V1 reads.
pub(super) fn open(root: &Path) -> Result<LocalStore, AppError> {
    LocalStore::open_precise(root)
}

#[cfg(all(test, feature = "keystore-file", feature = "parser-json"))]
mod tests;

/// Reopen only after validating the signed opt-in setting. Defaults use open unchanged.
pub(super) fn experimental(
    root: &Path,
    config: &irmind_app::PersistentConfig,
    registry: &irmind_app::modules::ModuleRegistry,
) -> Result<Option<LocalStore>, AppError> {
    if config.experimental_common_writer != Some(true) {
        return Ok(None);
    }
    if !cfg!(any(
        feature = "mapping-json-compat",
        feature = "mapping-journald-compat"
    )) {
        return Err(AppError::Policy(
            "experimental common writer is not compiled; enable mapping features".into(),
        ));
    }
    let catalog = registry.mapping_catalog()?;
    if !catalog.supports_decoder("parser-json", "json-source-v1")
        && !catalog.supports_decoder("parser-linux", "journald-source-v1")
    {
        return Err(AppError::Policy(
            "experimental common writer is not compiled; enable mapping features".into(),
        ));
    }
    LocalStore::open_mapped(root, std::sync::Arc::new(catalog)).map(Some)
}

pub(super) fn experimental_parsers(
    catalog: irmind_app::modules::ParserCatalog,
    config: &irmind_app::PersistentConfig,
) -> Result<irmind_app::modules::ParserCatalog, AppError> {
    if config.experimental_common_writer != Some(true) {
        return Ok(catalog);
    }
    if !cfg!(any(
        feature = "mapping-json-compat",
        feature = "mapping-journald-compat"
    )) {
        return Err(AppError::Policy(
            "experimental common writer is not compiled; enable mapping features".into(),
        ));
    }
    #[cfg(feature = "mapping-json-compat")]
    let catalog = catalog.with_experimental_parser(irmind_mod_parser_json::source_log_parser())?;
    #[cfg(feature = "mapping-journald-compat")]
    let catalog = catalog.with_experimental_parser(irmind_mod_parser_linux::source_log_parser())?;
    Ok(catalog)
}
