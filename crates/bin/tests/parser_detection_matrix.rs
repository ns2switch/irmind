#![forbid(unsafe_code)]
#![cfg(feature = "parser-json")]

use irmind_app::modules::{ModuleConfig, ModuleRegistry, ParserChoice};
use irmind_mod_parser_json::JsonParser;

#[test]
fn every_compiled_parser_fixture_has_one_high_confidence_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = ModuleRegistry::new();
    registry.register(Box::new(JsonParser), &ModuleConfig::new())?;
    let fixtures: &[(&str, &[u8], &str)] = &[(
        "hunteval-aws-iam-001.json",
        include_bytes!("../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json"),
        "parser-json",
    )];
    for (name, bytes, expected) in fixtures {
        let choice = registry.detect_parser(name, bytes);
        assert!(
            matches!(choice, ParserChoice::Auto(_)),
            "{name}: {choice:?}"
        );
        if let ParserChoice::Auto(candidate) = choice {
            assert_eq!(candidate.id, *expected, "{name}");
            assert!(candidate.confidence.is_high(), "{name}");
        }
    }
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
