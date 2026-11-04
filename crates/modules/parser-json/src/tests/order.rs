use super::*;
use irmind_app::CancellationToken;

fn report_rows(source: &str, input: &str) -> Vec<GraphRecord> {
    let mut rows = Vec::new();
    let report = JsonParser
        .parse_reader_report(
            source,
            &mut input.as_bytes(),
            [0; 32],
            &CancellationToken::new(),
            &mut |row| {
                row.inspect(|row| rows.push(row.clone()));
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
    assert_eq!(expected[0].entities.len(), 32);
    for (source, suffix) in [("row.ndjson", ""), ("row.json", "\n"), ("row.json", "")] {
        assert_eq!(report_rows(source, &format!("{forward}{suffix}")), expected);
        assert_eq!(report_rows(source, &format!("{reverse}{suffix}")), expected);
    }
}

#[test]
fn fast_lines_sort_nested_objects_after_unwrapping_and_preserve_array_order() {
    let raw = r#"{"result":{"_raw":"{\"z\":[{\"z\":2,\"a\":1},{\"z\":4,\"a\":3}],\"a\":{\"z\":2,\"a\":1}}"}}"#;
    let expected = r#"{"a":{"a":1,"z":2},"z":[{"a":1,"z":2},{"a":3,"z":4}]}"#;
    for source in ["nested.ndjson", "nested.json"] {
        let rows = report_rows(source, &format!("{raw}\n{raw}\n"));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.text == expected));
    }
}
