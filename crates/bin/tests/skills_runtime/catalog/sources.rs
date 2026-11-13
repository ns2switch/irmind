use irmind_app::modules::{Module, ModuleConfig, ModuleRegistry};
use std::{path::Path, sync::Arc};

pub(super) fn open(root: &Path) -> Arc<irmind_infra::LocalStore> {
    let mut registry = ModuleRegistry::new();
    for module in modules() {
        registry.register(module, &ModuleConfig::new()).unwrap();
    }
    Arc::new(
        irmind_infra::LocalStore::open_mapped(root, Arc::new(registry.mapping_catalog().unwrap()))
            .unwrap(),
    )
}

// Match the release's disjoint JSON/CloudTrail selectors, not the broad
// extraction-only compatibility fixture used by unrelated integration tests.
fn modules() -> Vec<Box<dyn Module>> {
    use irmind_mod_mapping_linux::{AuditMapping, HttpMapping};
    use irmind_mod_mapping_network::NetworkExtractionMapping;
    vec![
        Box::new(irmind_mod_parser_gcp_audit::GcpAuditParser::default()),
        Box::new(irmind_mod_mapping_gcp_audit::CloudAuditMapping::new().unwrap()),
        Box::new(irmind_mod_mapping_gcp_audit::GkeMapping::new().unwrap()),
        Box::new(irmind_mod_parser_json::JsonParser),
        Box::new(irmind_mod_mapping_json_compat::JsonCompatibilityMapping::generic_only().unwrap()),
        Box::new(irmind_mod_mapping_cloudtrail::CloudTrailMapping::new().unwrap()),
        Box::new(irmind_mod_parser_ecs::EcsParser),
        Box::new(irmind_mod_mapping_ecs::EcsMapping::new().unwrap()),
        Box::new(irmind_mod_parser_linux::LinuxParser),
        Box::new(AuditMapping::new().unwrap()),
        Box::new(HttpMapping::new().unwrap()),
        Box::new(irmind_mod_parser_zeek::ZeekParser),
        Box::new(NetworkExtractionMapping::new("parser-zeek").unwrap()),
        Box::new(irmind_mod_parser_suricata::SuricataParser),
        Box::new(NetworkExtractionMapping::new("parser-suricata").unwrap()),
    ]
}
