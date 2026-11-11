//! Integration fixtures use the same identified decoder and mapper ports as production.
#![allow(clippy::unwrap_used, dead_code, clippy::too_many_lines)]
use irmind_app::modules::{ModuleConfig, ModuleRegistry, ParserCatalog};
use irmind_infra::LocalStore;
use std::{path::Path, sync::Arc};
fn registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    #[cfg(feature = "parser-json")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_json::JsonParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-ecs")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_ecs::EcsParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_ecs::EcsMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-ocsf")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_ocsf::OcsfParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_ocsf::OcsfMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-syslog")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_syslog::SyslogParser::default()),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_syslog::SyslogExtractionMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-velociraptor")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_velociraptor::VelociraptorParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_dfir::DfirExtractionMapping::new("parser-velociraptor")
                        .unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-hayabusa")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_hayabusa::HayabusaParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_dfir::DfirExtractionMapping::new("parser-hayabusa").unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-chainsaw")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_chainsaw::ChainsawParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_dfir::DfirExtractionMapping::new("parser-chainsaw").unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-plaso")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_plaso::PlasoParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_dfir::DfirExtractionMapping::new("parser-plaso").unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-eztools")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_eztools::EztoolsParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_dfir::DfirExtractionMapping::new("parser-eztools").unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-zeek")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_zeek::ZeekParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_network::NetworkExtractionMapping::new("parser-zeek")
                        .unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-suricata")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_suricata::SuricataParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_network::NetworkExtractionMapping::new("parser-suricata")
                        .unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-linux")]
    {
        use irmind_mod_mapping_linux::{
            AuditMapping, AuthExtractionMapping, HttpMapping, SshdMapping, SuMapping, SudoMapping,
        };
        registry
            .register(
                Box::new(irmind_mod_parser_linux::LinuxParser::default()),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_journald_compat::JournaldCompatibilityMapping::new()
                        .unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();

        registry
            .register(Box::new(AuditMapping::new().unwrap()), &ModuleConfig::new())
            .unwrap();
        registry
            .register(
                Box::new(AuthExtractionMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(Box::new(HttpMapping::new().unwrap()), &ModuleConfig::new())
            .unwrap();
        registry
            .register(Box::new(SshdMapping::new().unwrap()), &ModuleConfig::new())
            .unwrap();
        registry
            .register(Box::new(SuMapping::new().unwrap()), &ModuleConfig::new())
            .unwrap();
        registry
            .register(Box::new(SudoMapping::new().unwrap()), &ModuleConfig::new())
            .unwrap();
    }
    registry
}
pub(super) fn open(root: &Path) -> LocalStore {
    LocalStore::open_mapped(root, Arc::new(registry().mapping_catalog().unwrap())).unwrap()
}
pub(super) fn catalog() -> ParserCatalog {
    let mut catalog = registry().parser_catalog();
    #[cfg(feature = "parser-json")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_json::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-ecs")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_ecs::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-ocsf")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_ocsf::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-syslog")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_syslog::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-linux")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_linux::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-velociraptor")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_velociraptor::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-hayabusa")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_hayabusa::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-chainsaw")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_chainsaw::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-plaso")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_plaso::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-eztools")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_eztools::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-zeek")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_zeek::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-suricata")]
    {
        catalog = catalog
            .with_experimental_parser(irmind_mod_parser_suricata::source_log_parser())
            .unwrap();
    }
    catalog
}

pub(super) fn parser(id: &str) -> Arc<dyn irmind_app::LogParser> {
    let catalog = catalog();
    let version = catalog
        .available()
        .into_iter()
        .find(|(name, _)| name == id)
        .unwrap()
        .1;
    catalog.get_version(id, &version).unwrap()
}
