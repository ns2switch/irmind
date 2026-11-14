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
    use irmind_mod_mapping_network::NetworkMapping;
    let mut modules: Vec<Box<dyn Module>> = vec![
        #[cfg(feature = "parser-kubernetes")]
        Box::new(irmind_mod_parser_kubernetes::KubernetesParser::default()),
        #[cfg(feature = "parser-falco")]
        Box::new(irmind_mod_parser_falco::FalcoParser::default()),
        #[cfg(feature = "parser-falco")]
        Box::new(irmind_mod_mapping_falco::HostMapping::new().unwrap()),
        #[cfg(feature = "parser-falco")]
        Box::new(irmind_mod_mapping_falco::KubernetesMapping::new().unwrap()),
        #[cfg(feature = "parser-falco")]
        Box::new(irmind_mod_mapping_falco::AuditPluginMapping::new().unwrap()),
        Box::new(irmind_mod_parser_entra::EntraParser),
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
        Box::new(NetworkMapping::new("parser-zeek").unwrap()),
        Box::new(irmind_mod_parser_suricata::SuricataParser),
        Box::new(NetworkMapping::new("parser-suricata").unwrap()),
    ];
    #[cfg(feature = "parser-kubernetes")]
    for mapper in irmind_mod_mapping_kubernetes::KubernetesMapping::all().unwrap() {
        modules.push(Box::new(mapper));
    }
    for mapper in irmind_mod_mapping_entra::EntraMapping::all().unwrap() {
        modules.push(Box::new(mapper));
    }
    modules
}
