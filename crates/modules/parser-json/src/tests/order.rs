use super::*;
use irmind_app::CancellationToken;

fn report_rows(source: &str, input: &str) -> Vec<irmind_domain::SourceValue> {
    let mut rows = Vec::new();
    let report = irmind_testkit::decode_source(
        &JsonSourceDecoder,
        source,
        &mut input.as_bytes(),
        [0; 32],
        &CancellationToken::new(),
        None,
        &mut |row| {
            row.inspect(|row| rows.push(row.fields().clone()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.rejected, 0);
    assert_eq!(report.accepted, rows.len());
    rows
}

#[test]
fn fast_line_and_single_object_paths_preserve_lexical_extraction_at_the_cap() {
    let fields = (0..40)
        .map(|n| format!("\"userName{n:02}\":\"synthetic-{n:02}\""))
        .collect::<Vec<_>>();
    let forward = format!("{{{}}}", fields.join(","));
    let reverse = format!(
        "{{{}}}",
        fields.iter().rev().cloned().collect::<Vec<_>>().join(",")
    );
    let expected = report_rows("whole.json", &forward);
    assert!(expected[0].field("userName39").is_some());
    for (source, suffix) in [("row.ndjson", ""), ("row.json", "\n"), ("row.json", "")] {
        assert_eq!(report_rows(source, &format!("{forward}{suffix}")), expected);
        assert_eq!(report_rows(source, &format!("{reverse}{suffix}")), expected);
    }
}

#[test]
fn raw_nested_strings_remain_original_and_decoded_arrays_keep_their_order() {
    let raw = r#"{"result":{"_raw":"{\"z\":[{\"z\":2,\"a\":1},{\"z\":4,\"a\":3}],\"a\":{\"z\":2,\"a\":1}}"}}"#;
    let expected = r#"{"z":[{"z":2,"a":1},{"z":4,"a":3}],"a":{"z":2,"a":1}}"#;
    for source in ["nested.ndjson", "nested.json"] {
        let rows = report_rows(source, &format!("{raw}\n{raw}\n"));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| {
            row.field("result")
                .unwrap()
                .field("_raw")
                .unwrap()
                .as_text()
                == Some(expected)
        }));
        let decoded = report_rows(source, &format!("{expected}\n"));
        assert_eq!(
            irmind_app::source_mapping::json::render_source_fields(&decoded[0]).unwrap(),
            r#"{"a":{"a":1,"z":2},"z":[{"a":1,"z":2},{"a":3,"z":4}]}"#
        );
    }
}
