//! Compile-time parser features select independently identified pure mappings.
use super::{ModuleRegistry, Result};
use irmind_app::modules::ModuleConfig;

#[cfg(feature = "mapping-dfir")]
const DFIR_PARSERS: &[&str] = &[
    #[cfg(feature = "parser-velociraptor")]
    "parser-velociraptor",
    #[cfg(feature = "parser-hayabusa")]
    "parser-hayabusa",
    #[cfg(feature = "parser-chainsaw")]
    "parser-chainsaw",
    #[cfg(feature = "parser-plaso")]
    "parser-plaso",
    #[cfg(feature = "parser-eztools")]
    "parser-eztools",
];

#[cfg(feature = "mapping-network")]
const NETWORK_PARSERS: &[&str] = &[
    #[cfg(feature = "parser-zeek")]
    "parser-zeek",
    #[cfg(feature = "parser-suricata")]
    "parser-suricata",
];

pub(super) fn register(registry: &mut ModuleRegistry) -> Result<()> {
    #[cfg(feature = "mapping-json-compat")]
    registry.register(Box::new(json_compatibility()?), &ModuleConfig::new())?;
    #[cfg(feature = "mapping-journald-compat")]
    registry.register(
        Box::new(irmind_mod_mapping_journald_compat::JournaldCompatibilityMapping::new()?),
        &ModuleConfig::new(),
    )?;
    #[cfg(any(feature = "mapping-kubernetes", feature = "mapping-falco"))]
    register_contextual(registry)?;
    #[cfg(feature = "mapping-cloudtrail")]
    registry.register(
        Box::new(irmind_mod_mapping_cloudtrail::CloudTrailMapping::new()?),
        &ModuleConfig::new(),
    )?;
    #[cfg(feature = "mapping-linux")]
    register_linux(registry)?;
    #[cfg(feature = "mapping-evtx")]
    register_evtx(registry)?;
    #[cfg(feature = "mapping-ecs")]
    registry.register(
        Box::new(irmind_mod_mapping_ecs::EcsMapping::new()?),
        &ModuleConfig::new(),
    )?;
    #[cfg(feature = "mapping-dfir")]
    for &parser in DFIR_PARSERS {
        let mapper = irmind_mod_mapping_dfir::DfirExtractionMapping::new(parser)?;
        registry.register(Box::new(mapper), &ModuleConfig::new())?;
    }
    #[cfg(feature = "mapping-syslog")]
    registry.register(
        Box::new(irmind_mod_mapping_syslog::SyslogExtractionMapping::new()?),
        &ModuleConfig::new(),
    )?;

    #[cfg(feature = "mapping-network")]
    for &parser in NETWORK_PARSERS {
        let mapper = irmind_mod_mapping_network::NetworkExtractionMapping::new(parser)?;
        registry.register(Box::new(mapper), &ModuleConfig::new())?;
    }

    #[cfg(feature = "mapping-ocsf")]
    registry.register(
        Box::new(irmind_mod_mapping_ocsf::OcsfMapping::new()?),
        &ModuleConfig::new(),
    )?;
    Ok(())
}
#[cfg(any(feature = "mapping-kubernetes", feature = "mapping-falco"))]
fn register_contextual(registry: &mut ModuleRegistry) -> Result<()> {
    #[cfg(feature = "mapping-kubernetes")]
    registry.register(
        Box::new(irmind_mod_mapping_kubernetes::KubernetesMapping::new()?),
        &ModuleConfig::new(),
    )?;
    #[cfg(feature = "mapping-falco")]
    {
        registry.register(
            Box::new(irmind_mod_mapping_falco::HostMapping::new()?),
            &ModuleConfig::new(),
        )?;
        registry.register(
            Box::new(irmind_mod_mapping_falco::KubernetesMapping::new()?),
            &ModuleConfig::new(),
        )?;
    }
    Ok(())
}
#[cfg(feature = "mapping-evtx")]
fn register_evtx(registry: &mut ModuleRegistry) -> Result<()> {
    use irmind_mod_mapping_evtx::{
        PowerShellMapping, SecurityMapping, SysmonMapping, SystemMapping,
    };
    for &event_id in SecurityMapping::EVENT_IDS {
        registry.register(
            Box::new(SecurityMapping::new(event_id)?),
            &ModuleConfig::new(),
        )?;
    }
    registry.register(Box::new(SystemMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(PowerShellMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(SysmonMapping::new()?), &ModuleConfig::new())?;
    Ok(())
}
#[cfg(feature = "mapping-linux")]
fn register_linux(registry: &mut ModuleRegistry) -> Result<()> {
    use irmind_mod_mapping_linux::{
        AuditMapping, AuthExtractionMapping, HttpMapping, SshdMapping, SuMapping, SudoMapping,
    };
    registry.register(Box::new(SshdMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(SudoMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(SuMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(HttpMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(AuditMapping::new()?), &ModuleConfig::new())?;
    registry.register(
        Box::new(AuthExtractionMapping::new()?),
        &ModuleConfig::new(),
    )?;
    Ok(())
}
#[cfg(feature = "mapping-json-compat")]
fn json_compatibility() -> Result<irmind_mod_mapping_json_compat::JsonCompatibilityMapping> {
    #[cfg(feature = "mapping-cloudtrail")]
    let mapper = irmind_mod_mapping_json_compat::JsonCompatibilityMapping::generic_only()?;
    #[cfg(not(feature = "mapping-cloudtrail"))]
    let mapper = irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new()?;
    Ok(mapper)
}
#[cfg(all(
    test,
    feature = "mapping-json-compat",
    feature = "mapping-journald-compat"
))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[test]
    fn compiled_mapping_modules_register_their_exact_ports() {
        let mut registry = ModuleRegistry::new();
        registry
            .add_source_decoder(Arc::new(irmind_mod_parser_json::JsonSourceDecoder))
            .unwrap();
        registry
            .add_source_decoder(Arc::new(irmind_mod_parser_linux::LinuxSourceDecoder))
            .unwrap();
        #[cfg(feature = "mapping-ecs")]
        registry
            .add_source_decoder(Arc::new(irmind_mod_parser_ecs::EcsSourceDecoder))
            .unwrap();
        #[cfg(feature = "mapping-evtx")]
        {
            let root = tempfile::tempdir().unwrap();
            registry
                .add_source_decoder(Arc::new(irmind_mod_parser_evtx::EvtxParser::new(
                    &root.path().join("missing-helper"),
                    root.path(),
                )))
                .unwrap();
        }
        #[cfg(feature = "mapping-dfir")]
        let decoders: Vec<Arc<dyn irmind_app::SourceDecoder>> = vec![
            #[cfg(feature = "parser-velociraptor")]
            Arc::new(irmind_mod_parser_velociraptor::VelociraptorSourceDecoder),
            #[cfg(feature = "parser-hayabusa")]
            Arc::new(irmind_mod_parser_hayabusa::HayabusaSourceDecoder),
            #[cfg(feature = "parser-chainsaw")]
            Arc::new(irmind_mod_parser_chainsaw::ChainsawSourceDecoder),
            #[cfg(feature = "parser-plaso")]
            Arc::new(irmind_mod_parser_plaso::PlasoSourceDecoder),
            #[cfg(feature = "parser-eztools")]
            Arc::new(irmind_mod_parser_eztools::EztoolsSourceDecoder),
        ];
        #[cfg(feature = "mapping-dfir")]
        for decoder in decoders {
            registry.add_source_decoder(decoder).unwrap();
        }
        #[cfg(feature = "mapping-syslog")]
        registry
            .add_source_decoder(Arc::new(irmind_mod_parser_syslog::SyslogSourceDecoder))
            .unwrap();

        #[cfg(feature = "mapping-network")]
        {
            #[cfg(feature = "parser-zeek")]
            registry
                .add_source_decoder(Arc::new(irmind_mod_parser_zeek::ZeekSourceDecoder))
                .unwrap();
            #[cfg(feature = "parser-suricata")]
            registry
                .add_source_decoder(Arc::new(irmind_mod_parser_suricata::SuricataSourceDecoder))
                .unwrap();
        }

        #[cfg(feature = "mapping-ocsf")]
        registry
            .add_source_decoder(Arc::new(irmind_mod_parser_ocsf::OcsfSourceDecoder))
            .unwrap();
        #[cfg(feature = "mapping-kubernetes")]
        registry
            .add_source_decoder(Arc::new(
                irmind_mod_parser_kubernetes::KubernetesSourceDecoder,
            ))
            .unwrap();
        #[cfg(feature = "mapping-falco")]
        registry
            .add_source_decoder(Arc::new(irmind_mod_parser_falco::FalcoSourceDecoder))
            .unwrap();
        register(&mut registry).unwrap();
        check_catalog(&registry);
    }
    fn check_catalog(registry: &ModuleRegistry) {
        let catalog = registry.mapping_catalog().unwrap();
        assert!(catalog.supports_decoder("parser-json", "json-source-v1"));
        assert!(catalog.supports_decoder("parser-linux", "linux-source-v1"));
        assert_eq!(
            catalog.snapshots().unwrap().len(),
            2 + 2 * usize::from(cfg!(feature = "mapping-falco"))
                + usize::from(cfg!(feature = "mapping-kubernetes"))
                + usize::from(cfg!(feature = "mapping-cloudtrail"))
                + usize::from(cfg!(feature = "mapping-syslog"))
                + 6 * usize::from(cfg!(feature = "mapping-linux"))
                + usize::from(cfg!(feature = "parser-zeek"))
                + usize::from(cfg!(feature = "parser-suricata"))
                + usize::from(cfg!(feature = "mapping-ecs"))
                + usize::from(cfg!(feature = "parser-velociraptor"))
                + usize::from(cfg!(feature = "parser-hayabusa"))
                + usize::from(cfg!(feature = "parser-chainsaw"))
                + usize::from(cfg!(feature = "parser-plaso"))
                + usize::from(cfg!(feature = "parser-eztools"))
                + usize::from(cfg!(feature = "mapping-ocsf"))
                + 20 * usize::from(cfg!(feature = "mapping-evtx"))
        );
    }
}
