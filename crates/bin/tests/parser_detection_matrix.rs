#![forbid(unsafe_code)]
#![cfg(feature = "parser-json")]

#[test]
fn existing_json_detection_rejects_unrelated_logs() -> Result<(), irmind_app::AppError> {
    use irmind_app::modules::{ModuleConfig, ModuleRegistry, ParserChoice};
    use irmind_mod_parser_json::JsonParser;

    let mut registry = ModuleRegistry::new();
    registry.register(Box::new(JsonParser), &ModuleConfig::new())?;
    let sample =
        include_bytes!("../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json");
    assert!(matches!(
        registry.detect_parser("cloud.json", sample),
        ParserChoice::Auto(_)
    ));
    assert!(matches!(
        registry.detect_parser("system.evtx", b"ElfFile\0"),
        ParserChoice::Unsupported
    ));
    assert!(matches!(
        registry.detect_parser(
            "auth.log",
            b"Oct 31 10:15:00 host sshd[1]: Accepted publickey"
        ),
        ParserChoice::Unsupported
    ));
    Ok(())
}

#[cfg(all(
    feature = "parser-ecs",
    feature = "parser-ocsf",
    feature = "parser-velociraptor",
    feature = "parser-hayabusa",
    feature = "parser-chainsaw",
    feature = "parser-plaso",
    feature = "parser-eztools"
))]
mod matrix {
    use irmind_app::{
        LogParser,
        modules::{ModuleConfig, ModuleRegistry, ParserChoice},
    };
    use irmind_mod_parser_chainsaw::ChainsawParser;
    use irmind_mod_parser_ecs::EcsParser;
    use irmind_mod_parser_eztools::EztoolsParser;
    use irmind_mod_parser_hayabusa::HayabusaParser;
    use irmind_mod_parser_json::JsonParser;
    use irmind_mod_parser_ocsf::OcsfParser;
    use irmind_mod_parser_plaso::PlasoParser;
    use irmind_mod_parser_velociraptor::VelociraptorParser;

    #[cfg(feature = "parser-suricata")]
    use irmind_mod_parser_suricata::SuricataParser;
    #[cfg(feature = "parser-zeek")]
    use irmind_mod_parser_zeek::ZeekParser;

    const JSON: &[u8] =
        include_bytes!("../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json");
    const ECS: &[u8] = include_bytes!("../../testkit/fixtures/parser-ecs/source/events.ndjson");
    const OCSF: &[u8] = include_bytes!("../../testkit/fixtures/parser-ocsf/source/events.ndjson");
    const VELOCIRAPTOR: &[u8] =
        include_bytes!("../../testkit/fixtures/parser-velociraptor/source/events.jsonl");
    const HAYABUSA: &[u8] =
        include_bytes!("../../testkit/fixtures/parser-hayabusa/source/events.jsonl");
    const CHAINSAW: &[u8] =
        include_bytes!("../../testkit/fixtures/parser-chainsaw/source/events.jsonl");
    const PLASO: &[u8] = include_bytes!("../../testkit/fixtures/parser-plaso/source/events.jsonl");
    const EZTOOLS: &[u8] =
        include_bytes!("../../testkit/fixtures/parser-eztools/source/events.csv");

    #[test]
    #[allow(clippy::too_many_lines)]
    fn each_fixture_has_one_unique_high_confidence_parser() -> Result<(), irmind_app::AppError> {
        let mut registry = ModuleRegistry::new();
        #[cfg(feature = "parser-google-workspace")]
        registry.register(
            Box::new(irmind_mod_parser_google_workspace::GoogleWorkspaceParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-macos")]
        registry.register(
            Box::new(irmind_mod_parser_macos::MacosParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-fdr")]
        registry.register(
            Box::new(irmind_mod_parser_fdr::FdrParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-defender")]
        registry.register(
            Box::new(irmind_mod_parser_defender::DefenderParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-email")]
        registry.register(
            Box::new(irmind_mod_parser_email::EmailParser),
            &ModuleConfig::new(),
        )?;

        #[cfg(feature = "parser-vpc-flow")]
        registry.register(
            Box::new(irmind_mod_parser_vpc_flow::VpcFlowParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-azure-flow")]
        registry.register(
            Box::new(irmind_mod_parser_azure_flow::AzureFlowParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-gcp-flow")]
        registry.register(
            Box::new(irmind_mod_parser_gcp_flow::GcpFlowParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-guardduty")]
        registry.register(
            Box::new(irmind_mod_parser_guardduty::GuardDutyParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-m365")]
        registry.register(
            Box::new(irmind_mod_parser_m365::M365Parser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-okta")]
        registry.register(
            Box::new(irmind_mod_parser_okta::OktaParser),
            &ModuleConfig::new(),
        )?;

        #[cfg(feature = "parser-zeek")]
        registry.register(Box::new(ZeekParser), &ModuleConfig::new())?;
        #[cfg(feature = "parser-suricata")]
        registry.register(Box::new(SuricataParser), &ModuleConfig::new())?;
        #[cfg(feature = "parser-kubernetes")]
        registry.register(
            Box::new(irmind_mod_parser_kubernetes::KubernetesParser::default()),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-falco")]
        registry.register(
            Box::new(irmind_mod_parser_falco::FalcoParser::default()),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-entra")]
        registry.register(
            Box::new(irmind_mod_parser_entra::EntraParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-gcp-audit")]
        registry.register(
            Box::new(irmind_mod_parser_gcp_audit::GcpAuditParser::default()),
            &ModuleConfig::new(),
        )?;
        registry.register(Box::new(JsonParser), &ModuleConfig::new())?;
        registry.register(Box::new(EcsParser), &ModuleConfig::new())?;
        registry.register(Box::new(OcsfParser), &ModuleConfig::new())?;
        registry.register(Box::new(VelociraptorParser), &ModuleConfig::new())?;
        registry.register(Box::new(HayabusaParser), &ModuleConfig::new())?;
        registry.register(Box::new(ChainsawParser), &ModuleConfig::new())?;
        registry.register(Box::new(PlasoParser), &ModuleConfig::new())?;
        registry.register(Box::new(EztoolsParser), &ModuleConfig::new())?;
        #[cfg(feature = "parser-linux")]
        registry.register(
            Box::new(irmind_mod_parser_linux::LinuxParser),
            &ModuleConfig::new(),
        )?;
        #[cfg(feature = "parser-syslog")]
        registry.register(
            Box::new(irmind_mod_parser_syslog::SyslogParser),
            &ModuleConfig::new(),
        )?;

        #[cfg(feature = "parser-declarative")]
        registry.register(
            Box::new(irmind_mod_parser_declarative::DeclarativeModule::new(
                custom_approved()?,
            )?),
            &ModuleConfig::new(),
        )?;
        let mut matrix: Matrix = std::collections::BTreeMap::new();
        for (name, sample, expected) in [
            #[cfg(feature = "parser-google-workspace")]
            (
                "workspace-events.ndjson",
                include_bytes!(
                    "../../testkit/fixtures/parser-google-workspace/source/events.ndjson"
                )
                .as_slice(),
                "parser-google-workspace",
            ),
            #[cfg(feature = "parser-google-workspace")]
            (
                "workspace-page.json",
                include_bytes!("../../testkit/fixtures/parser-google-workspace/source/page.json")
                    .as_slice(),
                "parser-google-workspace",
            ),
            #[cfg(feature = "parser-macos")]
            (
                "unified.ndjson",
                include_bytes!("../../testkit/fixtures/parser-macos/source/unified.ndjson")
                    .as_slice(),
                "parser-macos",
            ),
            #[cfg(feature = "parser-macos")]
            (
                "endpoint.ndjson",
                include_bytes!("../../testkit/fixtures/parser-macos/source/endpoint.ndjson")
                    .as_slice(),
                "parser-macos",
            ),
            #[cfg(feature = "parser-fdr")]
            (
                "fdr-events.ndjson",
                include_bytes!("../../testkit/fixtures/parser-fdr/source/events.ndjson").as_slice(),
                "parser-fdr",
            ),
            #[cfg(feature = "parser-defender")]
            (
                "defender-events.ndjson",
                include_bytes!("../../testkit/fixtures/parser-defender/source/events.ndjson")
                    .as_slice(),
                "parser-defender",
            ),
            #[cfg(feature = "parser-defender")]
            (
                "defender-api.json",
                include_bytes!("../../testkit/fixtures/parser-defender/source/api.json").as_slice(),
                "parser-defender",
            ),
            #[cfg(feature = "parser-defender")]
            (
                "defender-stream.json",
                include_bytes!("../../testkit/fixtures/parser-defender/source/stream.json")
                    .as_slice(),
                "parser-defender",
            ),
            #[cfg(feature = "parser-defender")]
            (
                "defender-hunting.csv",
                include_bytes!("../../testkit/fixtures/parser-defender/source/hunting.csv")
                    .as_slice(),
                "parser-defender",
            ),
            #[cfg(feature = "parser-email")]
            (
                "multipart.eml",
                include_bytes!("../../testkit/fixtures/parser-email/source/multipart.eml")
                    .as_slice(),
                "parser-email",
            ),
            #[cfg(feature = "parser-email")]
            (
                "headers.eml",
                include_bytes!("../../testkit/fixtures/parser-email/source/headers.eml").as_slice(),
                "parser-email",
            ),
            #[cfg(feature = "parser-email")]
            (
                "plain.eml",
                include_bytes!("../../testkit/fixtures/parser-email/source/plain.eml").as_slice(),
                "parser-email",
            ),
            #[cfg(feature = "parser-m365")]
            (
                "m365.ndjson",
                include_bytes!("../../testkit/fixtures/parser-m365/source/events.ndjson")
                    .as_slice(),
                "parser-m365",
            ),
            #[cfg(feature = "parser-m365")]
            (
                "purview.csv",
                include_bytes!("../../testkit/fixtures/parser-m365/source/purview.csv").as_slice(),
                "parser-m365",
            ),
            #[cfg(feature = "parser-okta")]
            (
                "okta.ndjson",
                include_bytes!("../../testkit/fixtures/parser-okta/source/events.ndjson")
                    .as_slice(),
                "parser-okta",
            ),
            #[cfg(feature = "parser-m365")]
            (
                "activity.json",
                include_bytes!("../../testkit/fixtures/parser-m365/source/activity.json")
                    .as_slice(),
                "parser-m365",
            ),
            #[cfg(feature = "parser-m365")]
            (
                "powershell.json",
                include_bytes!("../../testkit/fixtures/parser-m365/source/powershell.json")
                    .as_slice(),
                "parser-m365",
            ),
            #[cfg(feature = "parser-okta")]
            (
                "okta-api.json",
                include_bytes!("../../testkit/fixtures/parser-okta/source/api.json").as_slice(),
                "parser-okta",
            ),
            #[cfg(feature = "parser-guardduty")]
            (
                "guardduty-events.ndjson",
                include_bytes!("../../testkit/fixtures/parser-guardduty/source/events.ndjson")
                    .as_slice(),
                "parser-guardduty",
            ),
            #[cfg(feature = "parser-guardduty")]
            (
                "guardduty-api.json",
                include_bytes!("../../testkit/fixtures/parser-guardduty/source/api.json")
                    .as_slice(),
                "parser-guardduty",
            ),
            #[cfg(feature = "parser-guardduty")]
            (
                "guardduty-cli.json",
                include_bytes!("../../testkit/fixtures/parser-guardduty/source/cli.json")
                    .as_slice(),
                "parser-guardduty",
            ),
            #[cfg(feature = "parser-guardduty")]
            (
                "guardduty-eventbridge.json",
                include_bytes!("../../testkit/fixtures/parser-guardduty/source/eventbridge.json")
                    .as_slice(),
                "parser-guardduty",
            ),
            #[cfg(feature = "parser-vpc-flow")]
            (
                "vpc-flow-custom.log",
                include_bytes!("../../testkit/fixtures/parser-vpc-flow/source/custom.log")
                    .as_slice(),
                "parser-vpc-flow",
            ),
            #[cfg(feature = "parser-vpc-flow")]
            (
                "vpc-flow-cloudwatch.json",
                include_bytes!("../../testkit/fixtures/parser-vpc-flow/source/cloudwatch.json")
                    .as_slice(),
                "parser-vpc-flow",
            ),
            #[cfg(feature = "parser-azure-flow")]
            (
                "azure-flow-vnet.json",
                include_bytes!("../../testkit/fixtures/parser-azure-flow/source/vnet.json")
                    .as_slice(),
                "parser-azure-flow",
            ),
            #[cfg(feature = "parser-azure-flow")]
            (
                "azure-flow-vnet-v5.json",
                include_bytes!("../../testkit/fixtures/parser-azure-flow/source/vnet-v5.json")
                    .as_slice(),
                "parser-azure-flow",
            ),
            #[cfg(feature = "parser-azure-flow")]
            (
                "azure-flow-nsg-v1.json",
                include_bytes!("../../testkit/fixtures/parser-azure-flow/source/nsg-v1.json")
                    .as_slice(),
                "parser-azure-flow",
            ),
            #[cfg(feature = "parser-azure-flow")]
            (
                "azure-flow-nsg-v2.json",
                include_bytes!("../../testkit/fixtures/parser-azure-flow/source/nsg-v2.json")
                    .as_slice(),
                "parser-azure-flow",
            ),
            #[cfg(feature = "parser-azure-flow")]
            (
                "azure-flow-future.ndjson",
                include_bytes!("../../testkit/fixtures/parser-azure-flow/source/future.ndjson")
                    .as_slice(),
                "parser-azure-flow",
            ),
            #[cfg(feature = "parser-gcp-flow")]
            (
                "gcp-flow-events.ndjson",
                include_bytes!("../../testkit/fixtures/parser-gcp-flow/source/events.ndjson")
                    .as_slice(),
                "parser-gcp-flow",
            ),
            #[cfg(feature = "parser-gcp-flow")]
            (
                "gcp-flow-entries.json",
                include_bytes!("../../testkit/fixtures/parser-gcp-flow/source/entries.json")
                    .as_slice(),
                "parser-gcp-flow",
            ),
            #[cfg(feature = "parser-syslog")]
            (
                "synthetic.log",
                include_bytes!("../../testkit/fixtures/parser-syslog/source/events.log").as_slice(),
                "parser-syslog",
            ),
            #[cfg(feature = "parser-linux")]
            (
                "auth.log",
                include_bytes!("../../testkit/fixtures/parser-linux/source/auth.log").as_slice(),
                "parser-linux",
            ),
            #[cfg(feature = "parser-linux")]
            (
                "audit.log",
                include_bytes!("../../testkit/fixtures/parser-linux/source/audit.log").as_slice(),
                "parser-linux",
            ),
            #[cfg(feature = "parser-linux")]
            (
                "journal.jsonl",
                include_bytes!("../../testkit/fixtures/parser-linux/source/journal.jsonl")
                    .as_slice(),
                "parser-linux",
            ),
            #[cfg(feature = "parser-linux")]
            (
                "access.log",
                include_bytes!("../../testkit/fixtures/parser-linux/source/access.log").as_slice(),
                "parser-linux",
            ),
            #[cfg(feature = "parser-zeek")]
            (
                "events.log",
                include_bytes!("../../testkit/fixtures/parser-zeek/source/events.log").as_slice(),
                "parser-zeek",
            ),
            #[cfg(feature = "parser-zeek")]
            (
                "dns.jsonl",
                include_bytes!("../../testkit/fixtures/parser-zeek/source/dns.jsonl").as_slice(),
                "parser-zeek",
            ),
            #[cfg(feature = "parser-suricata")]
            (
                "eve.jsonl",
                include_bytes!("../../testkit/fixtures/parser-suricata/source/eve.jsonl")
                    .as_slice(),
                "parser-suricata",
            ),
            #[cfg(feature = "parser-gcp-audit")]
            (
                "gcp.ndjson",
                include_bytes!("../../testkit/fixtures/parser-gcp-audit/source/event.ndjson")
                    .as_slice(),
                "parser-gcp-audit",
            ),
            #[cfg(feature = "parser-gcp-audit")]
            (
                "gke.ndjson",
                include_bytes!("../../testkit/fixtures/parser-gcp-audit/source/gke.ndjson")
                    .as_slice(),
                "parser-gcp-audit",
            ),
            #[cfg(feature = "parser-gcp-audit")]
            (
                "gcp-array.json",
                include_bytes!("../../testkit/fixtures/parser-gcp-audit/source/gcp-array.json")
                    .as_slice(),
                "parser-gcp-audit",
            ),
            #[cfg(feature = "parser-gcp-audit")]
            (
                "gke-array.json",
                include_bytes!("../../testkit/fixtures/parser-gcp-audit/source/gke-array.json")
                    .as_slice(),
                "parser-gcp-audit",
            ),
            #[cfg(feature = "parser-entra")]
            (
                "signin-resource.ndjson",
                include_bytes!("../../testkit/fixtures/parser-entra/source/signin-resource.ndjson")
                    .as_slice(),
                "parser-entra",
            ),
            #[cfg(feature = "parser-entra")]
            (
                "signin-table.ndjson",
                include_bytes!("../../testkit/fixtures/parser-entra/source/signin-table.ndjson")
                    .as_slice(),
                "parser-entra",
            ),
            #[cfg(feature = "parser-entra")]
            (
                "audit-resource.ndjson",
                include_bytes!("../../testkit/fixtures/parser-entra/source/audit-resource.ndjson")
                    .as_slice(),
                "parser-entra",
            ),
            #[cfg(feature = "parser-entra")]
            (
                "audit-table.ndjson",
                include_bytes!("../../testkit/fixtures/parser-entra/source/audit-table.ndjson")
                    .as_slice(),
                "parser-entra",
            ),
            ("cloud.json", JSON, "parser-json"),
            #[cfg(feature = "parser-kubernetes")]
            (
                "kubernetes.ndjson",
                include_bytes!("../../testkit/fixtures/parser-kubernetes/source/events.ndjson")
                    .as_slice(),
                "parser-kubernetes",
            ),
            #[cfg(feature = "parser-kubernetes")]
            (
                "eks.json",
                include_bytes!("../../testkit/fixtures/parser-kubernetes/source/eks.json")
                    .as_slice(),
                "parser-kubernetes",
            ),
            #[cfg(feature = "parser-kubernetes")]
            (
                "aks.json",
                include_bytes!("../../testkit/fixtures/parser-kubernetes/source/aks.json")
                    .as_slice(),
                "parser-kubernetes",
            ),
            #[cfg(feature = "parser-kubernetes")]
            (
                "eks-row.ndjson",
                include_bytes!("../../testkit/fixtures/parser-kubernetes/source/eks-row.ndjson")
                    .as_slice(),
                "parser-kubernetes",
            ),
            #[cfg(feature = "parser-kubernetes")]
            (
                "aks-row.ndjson",
                include_bytes!("../../testkit/fixtures/parser-kubernetes/source/aks-row.ndjson")
                    .as_slice(),
                "parser-kubernetes",
            ),
            #[cfg(feature = "parser-falco")]
            (
                "falco-audit.ndjson",
                include_bytes!("../../testkit/fixtures/parser-falco/source/audit.ndjson")
                    .as_slice(),
                "parser-falco",
            ),
            #[cfg(feature = "parser-falco")]
            (
                "falco.ndjson",
                include_bytes!("../../testkit/fixtures/parser-falco/source/events.ndjson")
                    .as_slice(),
                "parser-falco",
            ),
            ("ecs.ndjson", ECS, "parser-ecs"),
            ("ocsf.ndjson", OCSF, "parser-ocsf"),
            ("velociraptor.jsonl", VELOCIRAPTOR, "parser-velociraptor"),
            ("hayabusa.jsonl", HAYABUSA, "parser-hayabusa"),
            ("chainsaw.jsonl", CHAINSAW, "parser-chainsaw"),
            ("plaso.jsonl", PLASO, "parser-plaso"),
            ("eztools.csv", EZTOOLS, "parser-eztools"),
        ] {
            let choice = registry.detect_parser(name, sample);
            let ParserChoice::Auto(found) = choice else {
                return Err(irmind_app::AppError::Policy(
                    "parser detection is ambiguous".into(),
                ));
            };
            #[cfg(feature = "parser-declarative")]
            for (id, _) in registry
                .parser_catalog()
                .available()
                .into_iter()
                .filter(|(id, _)| id.starts_with("parser-declarative-"))
            {
                assert!(registry.parser_by_id(&id)?.detect(name, sample).is_none());
            }
            assert_eq!(found.id, expected);
            assert!(found.confidence.is_high());
            assert_scores(name, sample, expected)?;
            matrix.insert(
                format!("{expected}/{name}"),
                capture_scores(&registry, name, sample)?,
            );
        }
        #[cfg(feature = "parser-declarative")]
        assert_custom_matrix(&registry, &mut matrix)?;
        if let Ok(path) = std::env::var("IRMIND_DETECTION_MATRIX_OUT") {
            let bytes = serde_json::to_vec_pretty(&matrix).map_err(|_| {
                irmind_app::AppError::Policy("cannot encode detection matrix".into())
            })?;
            std::fs::write(path, bytes).map_err(|_| {
                irmind_app::AppError::Policy("cannot write detection matrix".into())
            })?;
        }
        assert!(matches!(
            registry.detect_parser("security-lake.parquet", b"PAR1synthetic-header"),
            ParserChoice::NeedsAnalyst(_)
        ));
        Ok(())
    }
    type Matrix =
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, Option<u8>>>;
    fn capture_scores(
        registry: &ModuleRegistry,
        name: &str,
        sample: &[u8],
    ) -> Result<std::collections::BTreeMap<String, Option<u8>>, irmind_app::AppError> {
        registry
            .parser_catalog()
            .available()
            .into_iter()
            .map(|(id, _)| {
                let score = registry
                    .parser_by_id(&id)?
                    .detect(name, sample)
                    .map(irmind_app::ParserConfidence::value);
                Ok((id, score))
            })
            .collect()
    }
    fn assert_scores(
        name: &str,
        sample: &[u8],
        expected: &str,
    ) -> Result<(), irmind_app::AppError> {
        let observed = [
            ("parser-json", JsonParser.detect(name, sample)),
            ("parser-ecs", EcsParser.detect(name, sample)),
            ("parser-ocsf", OcsfParser.detect(name, sample)),
            (
                "parser-velociraptor",
                VelociraptorParser.detect(name, sample),
            ),
            ("parser-hayabusa", HayabusaParser.detect(name, sample)),
            ("parser-chainsaw", ChainsawParser.detect(name, sample)),
            ("parser-plaso", PlasoParser.detect(name, sample)),
            ("parser-eztools", EztoolsParser.detect(name, sample)),
        ];
        assert_additional_scores(name, sample, expected);
        let expected_scores: [Option<u8>; 8] = match expected {
            "parser-syslog" => [None; 8],
            "parser-linux"
            | "parser-zeek"
            | "parser-suricata"
            | "parser-kubernetes"
            | "parser-falco"
            | "parser-gcp-audit"
            | "parser-entra"
            | "parser-m365"
            | "parser-okta"
            | "parser-guardduty"
            | "parser-vpc-flow"
            | "parser-azure-flow"
            | "parser-gcp-flow"
            | "parser-defender"
            | "parser-fdr"
            | "parser-macos"
            | "parser-google-workspace" => [
                if matches!(sample.first(), Some(b'{' | b'[')) {
                    Some(45)
                } else {
                    None
                },
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            "parser-json" => [Some(90), None, None, None, None, None, None, None],
            "parser-ecs" => [Some(45), Some(95), None, None, None, None, None, None],
            "parser-ocsf" => [Some(45), None, Some(95), None, None, None, None, None],
            "parser-velociraptor" => [Some(45), None, None, Some(95), None, None, None, None],
            "parser-hayabusa" => [Some(45), None, None, None, Some(95), None, None, None],
            "parser-chainsaw" => [Some(45), None, None, None, None, Some(95), None, None],
            "parser-plaso" => [Some(45), None, None, None, None, None, Some(95), None],
            "parser-eztools" => [None, None, None, None, None, None, None, Some(95)],
            "parser-email" => [None, None, None, None, None, None, None, None],
            _ => {
                return Err(irmind_app::AppError::Policy(
                    "unknown parser fixture".into(),
                ));
            }
        };
        for ((id, confidence), score) in observed.into_iter().zip(expected_scores) {
            assert_eq!(confidence.map(irmind_app::ParserConfidence::value), score);
            if id != expected {
                assert!(!confidence.is_some_and(irmind_app::ParserConfidence::is_high));
            }
        }
        Ok(())
    }
    fn assert_priority_scores(name: &str, sample: &[u8], expected: &str) {
        #[cfg(feature = "parser-google-workspace")]
        assert_eq!(
            irmind_mod_parser_google_workspace::GoogleWorkspaceParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-google-workspace").then_some(98)
        );
        #[cfg(feature = "parser-macos")]
        assert_eq!(
            irmind_mod_parser_macos::MacosParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-macos").then_some(98)
        );
        #[cfg(feature = "parser-fdr")]
        assert_eq!(
            irmind_mod_parser_fdr::FdrParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-fdr").then_some(98)
        );
        #[cfg(feature = "parser-defender")]
        assert_eq!(
            irmind_mod_parser_defender::DefenderParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-defender").then_some(98)
        );
        #[cfg(feature = "parser-email")]
        assert_eq!(
            irmind_mod_parser_email::EmailParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-email").then_some(98)
        );
        #[cfg(feature = "parser-vpc-flow")]
        assert_eq!(
            irmind_mod_parser_vpc_flow::VpcFlowParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-vpc-flow").then_some(98)
        );
        #[cfg(feature = "parser-azure-flow")]
        assert_eq!(
            irmind_mod_parser_azure_flow::AzureFlowParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-azure-flow").then_some(98)
        );
        #[cfg(feature = "parser-gcp-flow")]
        assert_eq!(
            irmind_mod_parser_gcp_flow::GcpFlowParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-gcp-flow").then_some(98)
        );
        #[cfg(feature = "parser-guardduty")]
        assert_eq!(
            irmind_mod_parser_guardduty::GuardDutyParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-guardduty").then_some(98)
        );
        #[cfg(feature = "parser-m365")]
        assert_eq!(
            irmind_mod_parser_m365::M365Parser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-m365").then_some(98)
        );
        #[cfg(feature = "parser-okta")]
        assert_eq!(
            irmind_mod_parser_okta::OktaParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-okta").then_some(98)
        );
    }
    fn assert_additional_scores(name: &str, sample: &[u8], expected: &str) {
        assert_priority_scores(name, sample, expected);
        #[cfg(feature = "parser-entra")]
        assert_eq!(
            irmind_mod_parser_entra::EntraParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-entra").then_some(98)
        );
        #[cfg(feature = "parser-gcp-audit")]
        assert_eq!(
            irmind_mod_parser_gcp_audit::GcpAuditParser::default()
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-gcp-audit").then_some(98)
        );
        #[cfg(feature = "parser-kubernetes")]
        assert_eq!(
            irmind_mod_parser_kubernetes::KubernetesParser::default()
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-kubernetes").then_some(98)
        );
        #[cfg(feature = "parser-falco")]
        assert_eq!(
            irmind_mod_parser_falco::FalcoParser::default()
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-falco").then_some(98)
        );
        #[cfg(feature = "parser-syslog")]
        assert_eq!(
            irmind_mod_parser_syslog::SyslogParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            if expected == "parser-syslog" {
                Some(95)
            } else {
                None
            }
        );
        #[cfg(feature = "parser-linux")]
        assert_eq!(
            irmind_mod_parser_linux::LinuxParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            if expected == "parser-linux" {
                Some(95)
            } else {
                None
            }
        );
        #[cfg(feature = "parser-zeek")]
        assert_eq!(
            ZeekParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-zeek").then_some(95)
        );
        #[cfg(feature = "parser-suricata")]
        assert_eq!(
            SuricataParser
                .detect(name, sample)
                .map(irmind_app::ParserConfidence::value),
            (expected == "parser-suricata").then_some(95)
        );
    }
    #[cfg(feature = "parser-declarative")]
    #[allow(clippy::unwrap_used)]
    fn custom_approved() -> Result<Vec<irmind_app::ApprovedDefinition>, irmind_app::AppError> {
        use ed25519_dalek::{Signer as _, SigningKey};
        use irmind_app::{AppError, CryptoPorts, Engine, EnginePorts, Signer};
        use std::sync::Arc;
        struct TestSigner(SigningKey);
        impl Signer for TestSigner {
            fn actor(&self) -> irmind_domain::Actor {
                irmind_domain::Actor::Analyst
            }
            fn public_key(&self) -> Vec<u8> {
                self.0.verifying_key().to_bytes().to_vec()
            }
            fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
                Ok(self.0.sign(bytes).to_bytes().to_vec())
            }
        }
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(irmind_infra::LocalStore::open(root.path())?);
        let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[55; 32])));
        let engine = Engine::new(
            EnginePorts::new(
                store.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
                CryptoPorts::new(
                    signer.clone(),
                    Arc::new(irmind_infra::LocalVerifier::from_signer(signer.as_ref())),
                ),
                Arc::new(irmind_security::MandatoryGuard::new()?),
            ),
            irmind_domain::ExecutionMode::Attended,
            Arc::new(irmind_infra::SystemClock),
        )?;
        let definitions = irmind_infra::FileDefinitionStore::new(root.path());
        let compiler = irmind_mod_parser_declarative::DeclarativeCompiler;
        for text in [
            include_str!("../../../docs/examples/parsers/access-csv.toml"),
            include_str!("../../../docs/examples/parsers/nested-ndjson.toml"),
            include_str!("../../../docs/examples/parsers/auth-regex.toml"),
        ] {
            engine.install_parser_definition(&definitions, &compiler, text)?;
        }
        Ok(engine
            .approved_definitions()?
            .load_active(&definitions, &compiler)
            .0)
    }
    #[cfg(feature = "parser-declarative")]
    fn custom_parsers() -> Result<Vec<std::sync::Arc<dyn LogParser>>, irmind_app::AppError> {
        [
            include_str!("../../../docs/examples/parsers/access-csv.toml"),
            include_str!("../../../docs/examples/parsers/nested-ndjson.toml"),
            include_str!("../../../docs/examples/parsers/auth-regex.toml"),
        ]
        .into_iter()
        .map(|text| {
            Ok(
                std::sync::Arc::new(irmind_mod_parser_declarative::DeclarativeParser::from_toml(
                    text,
                )?) as std::sync::Arc<dyn LogParser>,
            )
        })
        .collect()
    }

    #[cfg(feature = "parser-declarative")]
    fn assert_custom_matrix(
        registry: &ModuleRegistry,
        matrix: &mut Matrix,
    ) -> Result<(), irmind_app::AppError> {
        let custom = custom_parsers()?;
        for (index, (name, sample)) in [
            (
                "custom.csv",
                include_bytes!("../../testkit/fixtures/parser-declarative/source/access.csv")
                    .as_slice(),
            ),
            (
                "custom.ndjson",
                include_bytes!("../../testkit/fixtures/parser-declarative/source/events.ndjson")
                    .as_slice(),
            ),
            (
                "custom.log",
                include_bytes!("../../testkit/fixtures/parser-declarative/source/auth.log")
                    .as_slice(),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            matrix.insert(
                format!("parser-declarative/{name}"),
                capture_scores(registry, name, sample)?,
            );
            let ParserChoice::NeedsAnalyst(candidates) = registry.detect_parser(name, sample)
            else {
                return Err(irmind_app::AppError::Policy(
                    "custom format must request analyst choice".into(),
                ));
            };
            assert!(
                candidates
                    .iter()
                    .all(|candidate| !candidate.confidence.is_high())
            );
            for (parser_index, parser) in custom.iter().enumerate() {
                assert_eq!(
                    parser
                        .detect(name, sample)
                        .map(irmind_app::ParserConfidence::value),
                    if parser_index == index {
                        Some(70)
                    } else {
                        None
                    }
                );
            }
            assert_eq!(
                JsonParser
                    .detect(name, sample)
                    .map(irmind_app::ParserConfidence::value),
                if index == 1 { Some(45) } else { None }
            );
            for native in [
                &EcsParser as &dyn LogParser,
                &OcsfParser,
                &VelociraptorParser,
                &HayabusaParser,
                &ChainsawParser,
                &PlasoParser,
                &EztoolsParser,
            ] {
                assert!(native.detect(name, sample).is_none());
            }
        }
        Ok(())
    }
}
