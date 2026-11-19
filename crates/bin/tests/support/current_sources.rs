//! Integration fixtures use the same identified decoder and mapper ports as production.
#![allow(clippy::unwrap_used, dead_code, clippy::too_many_lines)]
use irmind_app::modules::{ModuleConfig, ModuleRegistry, ParserCatalog};
use irmind_infra::LocalStore;
use std::{path::Path, sync::Arc};
fn registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    #[cfg(feature = "parser-elb")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_elb::ElbParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_elb::ElbMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-iis-w3c")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_iis_w3c::IisW3cParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_iis_w3c::IisW3cMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-windows-dns")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_windows_dns::WindowsDnsParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_windows_dns::WindowsDnsMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-route53")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_route53::Route53Parser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_route53::Route53Mapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-github-audit")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_github_audit::GitHubAuditParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_github_audit::GitHubAuditMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-google-workspace")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_google_workspace::GoogleWorkspaceParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(
                    irmind_mod_mapping_google_workspace::GoogleWorkspaceMapping::new().unwrap(),
                ),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-macos")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_macos::MacosParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_macos::MacosMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-fdr")]
    registry
        .register(
            Box::new(irmind_mod_parser_fdr::FdrParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "mapping-fdr")]
    registry
        .register(
            Box::new(irmind_mod_mapping_fdr::FdrMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "parser-defender")]
    registry
        .register(
            Box::new(irmind_mod_parser_defender::DefenderParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "mapping-defender")]
    registry
        .register(
            Box::new(irmind_mod_mapping_defender::DefenderMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "parser-email")]
    registry
        .register(
            Box::new(irmind_mod_parser_email::EmailParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "mapping-email")]
    registry
        .register(
            Box::new(irmind_mod_mapping_email::EmailMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "parser-vpc-flow")]
    registry
        .register(
            Box::new(irmind_mod_parser_vpc_flow::VpcFlowParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "parser-azure-flow")]
    registry
        .register(
            Box::new(irmind_mod_parser_azure_flow::AzureFlowParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "parser-gcp-flow")]
    registry
        .register(
            Box::new(irmind_mod_parser_gcp_flow::GcpFlowParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "parser-vpc-flow")]
    registry
        .register(
            Box::new(irmind_mod_mapping_cloud_flow::CloudFlowMapping::aws().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "parser-gcp-flow")]
    registry
        .register(
            Box::new(irmind_mod_mapping_cloud_flow::CloudFlowMapping::gcp().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "parser-azure-flow")]
    for mapper in irmind_mod_mapping_cloud_flow::CloudFlowMapping::azure().unwrap() {
        registry
            .register(Box::new(mapper), &ModuleConfig::new())
            .unwrap();
    }

    #[cfg(feature = "parser-guardduty")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_guardduty::GuardDutyParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_guardduty::GuardDutyMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }

    #[cfg(feature = "parser-m365")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_m365::M365Parser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_identity::IdentityMapping::m365().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-okta")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_okta::OktaParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_identity::IdentityMapping::okta().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }

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
                Box::new(irmind_mod_parser_syslog::SyslogParser),
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
                Box::new(irmind_mod_mapping_network::NetworkMapping::new("parser-zeek").unwrap()),
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
                    irmind_mod_mapping_network::NetworkMapping::new("parser-suricata").unwrap(),
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
                Box::new(irmind_mod_parser_linux::LinuxParser),
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
    #[cfg(feature = "parser-kubernetes")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_kubernetes::KubernetesParser::default()),
                &ModuleConfig::new(),
            )
            .unwrap();
        for mapper in irmind_mod_mapping_kubernetes::KubernetesMapping::all().unwrap() {
            registry
                .register(Box::new(mapper), &ModuleConfig::new())
                .unwrap();
        }
    }
    #[cfg(feature = "parser-falco")]
    {
        registry
            .register(
                Box::new(irmind_mod_mapping_falco::AuditPluginMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_parser_falco::FalcoParser::default()),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_falco::KubernetesMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_falco::HostMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "parser-entra")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_entra::EntraParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        for mapper in irmind_mod_mapping_entra::EntraMapping::all().unwrap() {
            registry
                .register(Box::new(mapper), &ModuleConfig::new())
                .unwrap();
        }
    }
    #[cfg(feature = "parser-gcp-audit")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_gcp_audit::GcpAuditParser::default()),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_gcp_audit::CloudAuditMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_gcp_audit::GkeMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
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
            .with_source_parser(irmind_mod_parser_json::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-ecs")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_ecs::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-ocsf")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_ocsf::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-syslog")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_syslog::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-linux")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_linux::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-velociraptor")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_velociraptor::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-hayabusa")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_hayabusa::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-chainsaw")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_chainsaw::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-plaso")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_plaso::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-eztools")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_eztools::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-zeek")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_zeek::source_log_parser())
            .unwrap();
    }
    #[cfg(feature = "parser-suricata")]
    {
        catalog = catalog
            .with_source_parser(irmind_mod_parser_suricata::source_log_parser())
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
