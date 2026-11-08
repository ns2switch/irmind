use super::*;
use crate::{EventOrigin, EvidenceHash};
use std::collections::BTreeMap;

fn record(fields: SourceValue) -> Result<SourceRecordV1, SourceRecordError> {
    SourceRecordV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([7; 32]),
            3,
            Some(42),
            "parser-json",
            "json-stream-v3",
        )
        .unwrap(),
        "logs/synthetic.json",
        None,
        SourceFormatV1::try_new("json", "source-json-v1", BTreeMap::new()).unwrap(),
        fields,
        DecodeAnnotationsV1::default(),
    )
}

fn canonical(value: &SourceRecordV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.feed_canonical(&mut |part| bytes.extend_from_slice(part));
    bytes
}

#[test]
fn exact_numbers_keep_type_precision_and_lexeme() {
    for value in [
        "0",
        "-0",
        "1",
        "9007199254740993",
        "-0.00000000000000001",
        "1e+99",
        "2E-12",
    ] {
        let number = SourceNumber::try_new(value).unwrap();
        assert_eq!(number.as_str(), value);
    }
    for value in [
        "", "+1", "01", "-", "1.", ".5", "NaN", "inf", "1e", "1e+-2", " 1", "1\n",
    ] {
        assert!(SourceNumber::try_new(value).is_err(), "{value:?}");
    }
    assert!(SourceNumber::try_new(&"1".repeat(129)).is_err());
}

#[test]
fn canonical_source_encoding_sorts_keys_and_distinguishes_types() {
    let make = |fields| record(SourceValue::object(fields).unwrap()).unwrap();
    let first = make(vec![
        ("z".into(), SourceValue::Null),
        ("a".into(), SourceValue::Text("1".into())),
    ]);
    let reordered = make(vec![
        ("a".into(), SourceValue::Text("1".into())),
        ("z".into(), SourceValue::Null),
    ]);
    assert_eq!(canonical(&first), canonical(&reordered));
    for other in [
        SourceValue::Number(SourceNumber::try_new("1").unwrap()),
        SourceValue::Bytes(b"1".to_vec()),
        SourceValue::Boolean(true),
    ] {
        assert_ne!(
            canonical(&first),
            canonical(&make(vec![
                ("z".into(), SourceValue::Null),
                ("a".into(), other)
            ]))
        );
    }
    assert!(
        SourceValue::object(vec![
            ("a".into(), SourceValue::Null),
            ("a".into(), SourceValue::Null)
        ])
        .is_err()
    );
    let mut changed_origin = first.clone();
    changed_origin.origin = EventOrigin::try_new(
        EvidenceHash::from_bytes([7; 32]),
        4,
        Some(42),
        "parser-json",
        "json-stream-v3",
    )
    .unwrap();
    assert_ne!(canonical(&first), canonical(&changed_origin));
}

#[test]
fn dotted_field_and_nested_field_are_not_aliases() {
    let fields = SourceValue::object(vec![
        ("source.ip".into(), SourceValue::Text("203.0.113.1".into())),
        (
            "source".into(),
            SourceValue::object(vec![("ip".into(), SourceValue::Text("203.0.113.2".into()))])
                .unwrap(),
        ),
    ])
    .unwrap();
    assert_eq!(
        SourcePath::keys(&["source.ip"])
            .unwrap()
            .resolve(&fields)
            .unwrap()
            .as_text(),
        Some("203.0.113.1")
    );
    assert_eq!(
        SourcePath::keys(&["source", "ip"])
            .unwrap()
            .resolve(&fields)
            .unwrap()
            .as_text(),
        Some("203.0.113.2")
    );
    assert!(SourcePath::keys(&[]).is_err());
}

#[test]
fn record_bounds_apply_to_whole_tree_and_original_annotations() {
    let mut deep = SourceValue::Null;
    for _ in 0..=SOURCE_MAX_DEPTH {
        deep = SourceValue::Array(vec![deep]);
    }
    assert!(record(SourceValue::object(vec![("deep".into(), deep)]).unwrap()).is_err());
    let huge = SourceValue::Array(vec![SourceValue::Null; SOURCE_MAX_NODES]);
    assert!(record(SourceValue::object(vec![("many".into(), huge)]).unwrap()).is_err());
    assert!(
        record(
            SourceValue::object(vec![(
                "text".into(),
                SourceValue::Text("x".repeat(SOURCE_MAX_BYTES))
            )])
            .unwrap()
        )
        .is_err()
    );
    assert!(
        DecodeAnnotationsV1::try_new(
            false,
            vec![
                SourceMemberV1 {
                    ordinal: 2,
                    offset: None
                };
                2
            ],
            None
        )
        .is_err()
    );
    let value = record(
        SourceValue::object(vec![(
            "secret".into(),
            SourceValue::Text("synthetic-sensitive-marker".into()),
        )])
        .unwrap(),
    )
    .unwrap();
    assert!(!format!("{value:?}").contains("synthetic-sensitive-marker"));
    assert!(!format!("{:?}", value.fields()).contains("synthetic-sensitive-marker"));
}
