use super::*;

fn assert_historical_parser(name: &str) {
    let (_, parser, bytes) = parsers()
        .into_iter()
        .find(|(id, _, _)| *id == name)
        .unwrap();
    let mut actual = Goldens::new();
    one_parser_golden(&mut actual, name, parser.as_ref(), bytes);
    let expected: Goldens =
        serde_json::from_str(include_str!("../fixtures/formats-readers-v3.json")).unwrap();
    for (key, bytes) in actual {
        assert_eq!(expected.get(&key), Some(&bytes), "{name}: {key}");
    }
}

macro_rules! ordered_parser_contract {
    ($test:ident, $name:literal) => {
        #[test]
        fn $test() {
            assert_historical_parser($name);
        }
    };
}
ordered_parser_contract!(ecs_json_features_keep_historical_bytes, "ecs");
ordered_parser_contract!(ocsf_json_features_keep_historical_bytes, "ocsf");
ordered_parser_contract!(
    velociraptor_json_features_keep_historical_bytes,
    "velociraptor"
);
ordered_parser_contract!(chainsaw_json_features_keep_historical_bytes, "chainsaw");
ordered_parser_contract!(plaso_json_features_keep_historical_bytes, "plaso");
ordered_parser_contract!(
    declarative_json_features_keep_historical_bytes,
    "declarative"
);

#[cfg(feature = "parser-linux")]
#[test]
fn journald_json_features_keep_historical_bytes() {
    let parser = irmind_mod_parser_linux::LinuxParser::from_version(
        "linux-v1:year=2026;offset=0;rollover=1;basis=analyst",
    )
    .unwrap();
    let mut actual = Goldens::new();
    one_parser_golden(
        &mut actual,
        "linux-journal",
        &parser,
        include_bytes!("../../../testkit/fixtures/parser-linux/source/journal.jsonl"),
    );
    let expected: Goldens =
        serde_json::from_str(include_str!("../fixtures/formats-linux-v1.json")).unwrap();
    for (key, bytes) in actual {
        assert_eq!(expected.get(&key), Some(&bytes), "journald: {key}");
    }
}

fn assert_fast_json_order(source: &str, trailing_newline: bool) {
    let fields = (0..40)
        .map(|n| format!("\"userName{n:02}\":\"synthetic-{n:02}\""))
        .collect::<Vec<_>>();
    let mut reverse = fields.clone();
    reverse.reverse();
    let suffix = if trailing_newline { "\n" } else { "" };
    let mut output = Vec::new();
    let input = format!("{{{}}}{suffix}", reverse.join(","));
    let report = JsonParser
        .parse_reader_report(
            source,
            &mut input.as_bytes(),
            [0; 32],
            &CancellationToken::new(),
            &mut |row| {
                row.inspect(|row| output.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(output[0].text, format!("{{{}}}", fields.join(",")));
    assert_eq!(output[0].entities.len(), 32);
    assert!(
        output[0]
            .entities
            .iter()
            .all(|(_, v)| v.as_str() <= "synthetic-31")
    );
}

#[test]
fn json_ndjson_fast_path_keeps_released_lexical_extraction() {
    assert_fast_json_order("synthetic.ndjson", false);
}
#[test]
fn json_single_object_fast_path_keeps_released_lexical_extraction() {
    assert_fast_json_order("synthetic.json", true);
}
