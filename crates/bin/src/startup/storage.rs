use irmind_app::AppError;
use irmind_infra::LocalStore;
use std::path::Path;

/// Open the local repository before its registered mapping catalog is composed.
pub(super) fn open(root: &Path) -> Result<LocalStore, AppError> {
    LocalStore::open_precise(root)
}

#[cfg(all(test, feature = "keystore-file", feature = "parser-json"))]
mod tests;

/// Bind the current writer and reconstruction to the same registered catalog.
pub(super) fn experimental(
    root: &Path,
    _config: &irmind_app::PersistentConfig,
    registry: &irmind_app::modules::ModuleRegistry,
) -> Result<Option<LocalStore>, AppError> {
    let catalog = registry.mapping_catalog()?;
    LocalStore::open_mapped(root, std::sync::Arc::new(catalog)).map(Some)
}

pub(super) fn experimental_parsers(
    catalog: irmind_app::modules::ParserCatalog,
    _config: &irmind_app::PersistentConfig,
    registry: &irmind_app::modules::ModuleRegistry,
) -> Result<irmind_app::modules::ParserCatalog, AppError> {
    #[cfg(feature = "mapping-json-compat")]
    let catalog = catalog.with_experimental_parser(irmind_mod_parser_json::source_log_parser())?;
    #[cfg(any(feature = "mapping-journald-compat", feature = "mapping-linux"))]
    let catalog = catalog.with_experimental_parser(irmind_mod_parser_linux::source_log_parser())?;
    #[cfg(feature = "mapping-ecs")]
    let catalog = catalog.with_experimental_parser(irmind_mod_parser_ecs::source_log_parser())?;
    #[cfg(feature = "mapping-dfir")]
    let catalog = dfir_sources(catalog)?;
    #[cfg(feature = "mapping-syslog")]
    let catalog = if catalog
        .available()
        .iter()
        .any(|(id, _)| id == "parser-syslog")
    {
        catalog.with_experimental_parser(irmind_mod_parser_syslog::source_log_parser())?
    } else {
        catalog
    };

    #[cfg(feature = "mapping-network")]
    let catalog = network_sources(catalog)?;

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

#[cfg(feature = "mapping-dfir")]
fn dfir_sources(
    mut catalog: irmind_app::modules::ParserCatalog,
) -> Result<irmind_app::modules::ParserCatalog, AppError> {
    let parsers: Vec<std::sync::Arc<dyn irmind_app::LogParser>> = vec![
        #[cfg(feature = "parser-velociraptor")]
        irmind_mod_parser_velociraptor::source_log_parser(),
        #[cfg(feature = "parser-hayabusa")]
        irmind_mod_parser_hayabusa::source_log_parser(),
        #[cfg(feature = "parser-chainsaw")]
        irmind_mod_parser_chainsaw::source_log_parser(),
        #[cfg(feature = "parser-plaso")]
        irmind_mod_parser_plaso::source_log_parser(),
        #[cfg(feature = "parser-eztools")]
        irmind_mod_parser_eztools::source_log_parser(),
    ];
    for parser in parsers {
        if catalog
            .available()
            .iter()
            .any(|(id, _)| id == parser.identity().name)
        {
            catalog = catalog.with_experimental_parser(parser)?;
        }
    }
    Ok(catalog)
}

#[cfg(feature = "mapping-network")]
fn network_sources(
    mut catalog: irmind_app::modules::ParserCatalog,
) -> Result<irmind_app::modules::ParserCatalog, AppError> {
    let parsers: Vec<std::sync::Arc<dyn irmind_app::LogParser>> = vec![
        #[cfg(feature = "parser-zeek")]
        irmind_mod_parser_zeek::source_log_parser(),
        #[cfg(feature = "parser-suricata")]
        irmind_mod_parser_suricata::source_log_parser(),
    ];
    for parser in parsers {
        if catalog
            .available()
            .iter()
            .any(|(id, _)| id == parser.identity().name)
        {
            catalog = catalog.with_experimental_parser(parser)?;
        }
    }
    Ok(catalog)
}
