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
            .add_source_decoder(Arc::new(irmind_mod_parser_linux::JournalSourceDecoder))
            .unwrap();
        register(&mut registry).unwrap();
        let catalog = registry.mapping_catalog().unwrap();
        assert!(catalog.supports_decoder("parser-json", "json-source-v1"));
        assert!(catalog.supports_decoder("parser-linux", "journald-source-v1"));
        assert_eq!(
            catalog.snapshots().unwrap().len(),
            2 + usize::from(cfg!(feature = "mapping-cloudtrail"))
        );
    }
}
