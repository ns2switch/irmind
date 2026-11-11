use super::*;
use irmind_app::SourceMapper;

fn assert_fast_json_order(source: &str, trailing_newline: bool) {
    let fields = (0..40)
        .map(|n| format!("\"userName{n:02}\":\"synthetic-{n:02}\""))
        .collect::<Vec<_>>();
    let mut reverse = fields.clone();
    reverse.reverse();
    let suffix = if trailing_newline { "\n" } else { "" };
    let mut output = Vec::new();
    let input = format!("{{{}}}{suffix}", reverse.join(","));
    let mapping = irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap();
    let report = irmind_testkit::decode_source(
        &irmind_mod_parser_json::JsonSourceDecoder,
        source,
        &mut input.as_bytes(),
        [0; 32],
        &CancellationToken::new(),
        None,
        &mut |row| {
            row.inspect(|record| {
                output.push(mapping.map(record).unwrap().record().indexed.record.clone());
            });
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
