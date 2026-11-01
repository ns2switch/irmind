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
    fn each_fixture_has_one_unique_high_confidence_parser() -> Result<(), irmind_app::AppError> {
        let mut registry = ModuleRegistry::new();
        registry.register(Box::new(JsonParser), &ModuleConfig::new())?;
        registry.register(Box::new(EcsParser), &ModuleConfig::new())?;
        registry.register(Box::new(OcsfParser), &ModuleConfig::new())?;
        registry.register(Box::new(VelociraptorParser), &ModuleConfig::new())?;
        registry.register(Box::new(HayabusaParser), &ModuleConfig::new())?;
        registry.register(Box::new(ChainsawParser), &ModuleConfig::new())?;
        registry.register(Box::new(PlasoParser), &ModuleConfig::new())?;
        registry.register(Box::new(EztoolsParser), &ModuleConfig::new())?;

        for (name, sample, expected) in [
            ("cloud.json", JSON, "parser-json"),
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
            assert_eq!(found.id, expected);
            assert!(found.confidence.is_high());
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
            let expected_scores: [Option<u8>; 8] = match expected {
                "parser-json" => [Some(90), None, None, None, None, None, None, None],
                "parser-ecs" => [Some(45), Some(95), None, None, None, None, None, None],
                "parser-ocsf" => [Some(45), None, Some(95), None, None, None, None, None],
                "parser-velociraptor" => [Some(45), None, None, Some(95), None, None, None, None],
                "parser-hayabusa" => [Some(45), None, None, None, Some(95), None, None, None],
                "parser-chainsaw" => [Some(45), None, None, None, None, Some(95), None, None],
                "parser-plaso" => [Some(45), None, None, None, None, None, Some(95), None],
                "parser-eztools" => [None, None, None, None, None, None, None, Some(95)],
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
        }
        assert!(matches!(
            registry.detect_parser("security-lake.parquet", b"PAR1synthetic-header"),
            ParserChoice::NeedsAnalyst(_)
        ));
        Ok(())
    }
}
