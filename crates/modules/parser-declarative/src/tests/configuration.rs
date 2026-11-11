use super::*;

const CSV: &str = include_str!("../../../../../docs/examples/parsers/access-csv.toml");
const JSON: &str = include_str!("../../../../../docs/examples/parsers/nested-ndjson.toml");
const REGEX: &str = include_str!("../../../../../docs/examples/parsers/auth-regex.toml");

#[test]
fn supplied_examples_compile_and_detect_only_their_synthetic_format() {
    let sources = [
        "time,host,user,source_ip,action,outcome\n2026-10-23T10:00:00Z,demo,alice,203.0.113.77,login,success\n",
        "{\"custom_event\":{\"time\":\"2026-10-23T10:00:00Z\",\"host\":\"demo\",\"action\":\"login\"}}\n",
        "2026-10-23T10:00:00Z host=demo user=alice src=203.0.113.77 action=login result=success\n",
    ];
    for (index, definition) in [CSV, JSON, REGEX].iter().enumerate() {
        let parser = DeclarativeParser::from_toml(definition).unwrap();
        assert!(parser.description().starts_with("Synthetic"));
        for (candidate, source) in sources.iter().enumerate() {
            assert_eq!(
                parser.detect_sample(source.as_bytes()).is_some(),
                index == candidate
            );
        }
        let (report, rows) = parse(definition, sources[index]);
        assert_eq!(report.accepted, 1);
        assert_eq!(report.rejected, 0);
        rows[0]
            .inspect(|record| assert!(record.entities.contains(&("host".into(), "demo".into()))));
    }
}

#[test]
fn invalid_definitions_and_excessive_limits_fail_closed() {
    for definition in [
        SIMPLE.replace("version = 1", "version = 2"),
        SIMPLE.replace("confidence = 70", "confidence = 80"),
        SIMPLE.replace(
            "default_timezone = \"UTC\"",
            "default_timezone = \"Europe/London\"",
        ),
        SIMPLE.to_owned() + "\n[limits]\ndepth = 1000\n",
        SIMPLE.to_owned() + "\n[limits]\nrecord_bytes = 2000000\n",
        SIMPLE.to_owned() + "\n[limits]\nrecords = 0\n",
        SIMPLE.to_owned() + "\napi_key = \"synthetic-secret\"\n",
    ] {
        assert!(DeclarativeParser::from_toml(&definition).is_err());
    }
    assert!(DeclarativeParser::from_toml(&"x".repeat(65537)).is_err());
}

#[test]
fn hash_pins_exact_definition_bytes_and_debug_omits_definition_content() {
    let a = DeclarativeParser::from_toml(SIMPLE).unwrap();
    let b =
        DeclarativeParser::from_toml(&(SIMPLE.to_owned() + "\n# synthetic revision\n")).unwrap();
    assert_eq!(a.id(), b.id());
    assert_ne!(a.definition_version(), b.definition_version());
    assert!(a.definition_version().len() <= 128);
    assert!(!format!("{a:?}").contains("Synthetic event"));
    assert!(!format!("{a:?}").contains("rfc3339"));
}

#[test]
fn backtracking_syntax_and_missing_regex_captures_are_rejected() {
    for definition in [
        REGEX.replace("(?P<time>[^ ]+)", "(?P<time>(a)\\1)"),
        REGEX.replace("time = \"time\"", "time = \"unknown\""),
    ] {
        assert!(DeclarativeParser::from_toml(&definition).is_err());
    }
}

#[test]
fn declarative_formats_pass_the_common_streaming_contract() {
    for (definition, source, fixture, expected) in [
        (
            include_str!("../../../../../docs/examples/parsers/access-csv.toml"),
            "access.csv",
            include_bytes!("../../../../testkit/fixtures/parser-declarative/source/access.csv")
                .as_slice(),
            1,
        ),
        (
            include_str!("../../../../../docs/examples/parsers/nested-ndjson.toml"),
            "events.ndjson",
            include_bytes!("../../../../testkit/fixtures/parser-declarative/source/events.ndjson")
                .as_slice(),
            2,
        ),
        (
            include_str!("../../../../../docs/examples/parsers/auth-regex.toml"),
            "auth.log",
            include_bytes!("../../../../testkit/fixtures/parser-declarative/source/auth.log")
                .as_slice(),
            1,
        ),
    ] {
        irmind_testkit::run_log_parser_contract(
            &DeclarativeParser::from_toml(definition).unwrap(),
            crate::pipeline::compile(definition)
                .unwrap()
                .decoder()
                .as_ref(),
            source,
            fixture,
            expected,
            None,
        )
        .unwrap();
    }
}
