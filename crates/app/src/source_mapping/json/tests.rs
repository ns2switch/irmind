use super::*;

#[test]
fn original_numbers_strings_and_dotted_keys_survive_without_map_order_features() {
    let raw = br#"{"z":9007199254740993,"n":1.00000000000000000001,"source.ip":"203.0.113.1","source":{"ip":"203.0.113.2"},"text":"1.0","array":[null,true]}"#;
    let fields = decode_json_fields(raw, SourceJsonLimits::default()).unwrap();
    assert_eq!(
        render_source_fields(&fields).unwrap(),
        r#"{"array":[null,true],"n":1.00000000000000000001,"source":{"ip":"203.0.113.2"},"source.ip":"203.0.113.1","text":"1.0","z":9007199254740993}"#
    );
    for invalid in [
        br#"{"x":1,"x":2}"#.as_slice(),
        br#"{"x":{"a":1,"a":2}}"#,
        br#"{"x":01}"#,
        br#"{"x":[1,]}"#,
        br#"{"x":truex}"#,
        b"{\"x\":\"\xff\"}",
    ] {
        assert!(decode_json_fields(invalid, SourceJsonLimits::default()).is_err());
    }
}

#[test]
fn source_limits_are_applied_before_a_whole_unbounded_tree_is_allocated() {
    let raw = br#"{"a":[{"b":"value"}]}"#;
    for limits in [
        SourceJsonLimits {
            bytes: 8,
            ..SourceJsonLimits::default()
        },
        SourceJsonLimits {
            fields: 1,
            ..SourceJsonLimits::default()
        },
        SourceJsonLimits {
            nodes: 2,
            ..SourceJsonLimits::default()
        },
        SourceJsonLimits {
            depth: 1,
            ..SourceJsonLimits::default()
        },
    ] {
        assert!(decode_json_fields(raw, limits).is_err());
    }
    assert!(decode_json_fields(br#"{"x":{}}"#, SourceJsonLimits::default()).is_ok());
}
