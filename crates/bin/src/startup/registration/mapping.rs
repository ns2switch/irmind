//! Pure mapping modules are optional; composition keeps the historical writer.
use super::{ModuleRegistry, Result};
use irmind_app::modules::ModuleConfig;

pub(super) fn register(registry: &mut ModuleRegistry) -> Result<()> {
    #[cfg(feature = "mapping-json-compat")]
    registry.register(Box::new(json_compatibility()?), &ModuleConfig::new())?;
    #[cfg(feature = "mapping-journald-compat")]
    registry.register(
        Box::new(irmind_mod_mapping_journald_compat::JournaldCompatibilityMapping::new()?),
        &ModuleConfig::new(),
    )?;
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
    #[cfg(feature = "mapping-ocsf")]
    registry.register(
        Box::new(irmind_mod_mapping_ocsf::OcsfMapping::new()?),
        &ModuleConfig::new(),
    )?;
    #[cfg(feature = "mapping-dfir")]
    for mapper in irmind_mod_mapping_dfir::DfirExtractionMapping::all()? {
        registry.register(Box::new(mapper), &ModuleConfig::new())?;
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
        AuditMapping, HttpMapping, SshdMapping, SuMapping, SudoMapping,
    };
    registry.register(Box::new(SshdMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(SudoMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(SuMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(HttpMapping::new()?), &ModuleConfig::new())?;
    registry.register(Box::new(AuditMapping::new()?), &ModuleConfig::new())?;
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
        #[cfg(feature = "mapping-ocsf")]
        registry
            .add_source_decoder(Arc::new(irmind_mod_parser_ocsf::OcsfSourceDecoder))
            .unwrap();
        #[cfg(feature = "mapping-dfir")]
        for decoder in [
            Arc::new(irmind_mod_parser_velociraptor::VelociraptorSourceDecoder)
                as Arc<dyn irmind_app::SourceDecoder>,
            Arc::new(irmind_mod_parser_hayabusa::HayabusaSourceDecoder),
            Arc::new(irmind_mod_parser_chainsaw::ChainsawSourceDecoder),
            Arc::new(irmind_mod_parser_plaso::PlasoSourceDecoder),
            Arc::new(irmind_mod_parser_eztools::EztoolsSourceDecoder),
        ] {
            registry.add_source_decoder(decoder).unwrap();
        }
        register(&mut registry).unwrap();
        let catalog = registry.mapping_catalog().unwrap();
        assert!(catalog.supports_decoder("parser-json", "json-source-v1"));
        assert!(catalog.supports_decoder("parser-linux", "linux-source-v1"));
        assert_eq!(
            catalog.snapshots().unwrap().len(),
            2 + usize::from(cfg!(feature = "mapping-cloudtrail"))
                + 5 * usize::from(cfg!(feature = "mapping-linux"))
                + usize::from(cfg!(feature = "mapping-ecs"))
                + usize::from(cfg!(feature = "mapping-ocsf"))
                + 5 * usize::from(cfg!(feature = "mapping-dfir"))
                + 20 * usize::from(cfg!(feature = "mapping-evtx"))
        );
    }
}
