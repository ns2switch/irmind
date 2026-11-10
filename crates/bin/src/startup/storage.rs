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
        feature = "mapping-journald-compat",
        feature = "mapping-linux",
        feature = "mapping-ecs",
        feature = "mapping-ocsf",
        feature = "mapping-evtx",
        feature = "parser-declarative"
    )) {
        return Err(AppError::Policy(
            "experimental common writer is not compiled; enable mapping features".into(),
        ));
    }
    let catalog = registry.mapping_catalog()?;
    if !catalog.supports_decoder("parser-json", "json-source-v1")
        && !catalog.supports_decoder("parser-linux", "linux-source-v1")
        && !catalog.supports_decoder("parser-ecs", "ecs-source-v1")
        && !catalog.supports_decoder("parser-ocsf", "ocsf-source-v1")
        && !catalog.supports_decoder("parser-evtx", "evtx-source-v1")
        && !registry
            .parser_catalog()
            .available()
            .iter()
            .any(|(id, version)| {
                id.starts_with("parser-declarative-") && catalog.supports_decoder(id, version)
            })
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
    registry: &irmind_app::modules::ModuleRegistry,
) -> Result<irmind_app::modules::ParserCatalog, AppError> {
    if config.experimental_common_writer != Some(true) {
        return Ok(catalog);
    }
    if !cfg!(any(
        feature = "mapping-json-compat",
        feature = "mapping-journald-compat",
        feature = "mapping-linux",
        feature = "mapping-ecs",
        feature = "mapping-ocsf",
        feature = "mapping-evtx",
        feature = "parser-declarative"
    )) {
        return Err(AppError::Policy(
            "experimental common writer is not compiled; enable mapping features".into(),
        ));
    }
    #[cfg(feature = "mapping-json-compat")]
    let catalog = catalog.with_experimental_parser(irmind_mod_parser_json::source_log_parser())?;
    #[cfg(any(feature = "mapping-journald-compat", feature = "mapping-linux"))]
    let catalog = catalog.with_experimental_parser(irmind_mod_parser_linux::source_log_parser())?;
    #[cfg(feature = "mapping-ecs")]
    let catalog = catalog.with_experimental_parser(irmind_mod_parser_ecs::source_log_parser())?;
    #[cfg(feature = "mapping-ocsf")]
    let catalog = if catalog
        .available()
        .iter()
        .any(|(id, _)| id == "parser-ocsf")
    {
        catalog.with_experimental_parser(irmind_mod_parser_ocsf::source_log_parser())?
    } else {
        catalog
    };
    let mappings = registry.mapping_catalog()?;
    #[cfg(feature = "mapping-evtx")]
    let catalog = if mappings
        .supports_decoder("parser-evtx", irmind_mod_parser_evtx::SOURCE_VERSION)
        && catalog
            .available()
            .iter()
            .any(|(id, _)| id == "parser-evtx")
    {
        catalog.with_experimental_parser(std::sync::Arc::new(
            mappings
                .decoder_selection("parser-evtx", irmind_mod_parser_evtx::SOURCE_VERSION)
                .map_err(irmind_app::source_mapping::MappingError::into_app)?
                .with_detector(irmind_mod_parser_evtx::detect_source),
        ))?
    } else {
        catalog
    };
    let mut catalog = catalog;
    for (id, version) in catalog.available() {
        if id.starts_with("parser-declarative-") && mappings.supports_decoder(&id, &version) {
            let selector = mappings
                .decoder_selection(&id, &version)
                .map_err(irmind_app::source_mapping::MappingError::into_app)?
                .with_selector(catalog.get(&id)?)?;
            catalog = catalog.with_experimental_parser(std::sync::Arc::new(selector))?;
        }
    }
    Ok(catalog)
}
