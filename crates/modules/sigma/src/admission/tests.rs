use super::*;

const RULE: &str = "title: Fixture\nlogsource: {product: windows}\ndetection: {selection: {Image: test.exe}, condition: selection}\n";

fn extra(body: &str) -> Result<RuleDocument, AdmissionError> {
    admit_rule(format!("{RULE}{body}").as_bytes())
}

#[test]
fn typed_scalars_do_not_coerce_quoted_text() {
    let rule =
        extra("metadata: [null, false, 17, 0x10, 0o10, 3.5, 'false', '17', ~, yes]").unwrap();
    assert_eq!(
        rule.fields().get("metadata"),
        Some(&RuleValue::Sequence(vec![
            RuleValue::Null,
            RuleValue::Boolean(false),
            RuleValue::Integer(17),
            RuleValue::Integer(16),
            RuleValue::Integer(8),
            RuleValue::Decimal("3.5".into()),
            RuleValue::Text("false".into()),
            RuleValue::Text("17".into()),
            RuleValue::Null,
            RuleValue::Text("yes".into()),
        ]))
    );
    for number in ["9223372036854775808", "1e9999", ".nan", "+.Inf"] {
        assert_eq!(
            extra(&format!("metadata: {number}")).unwrap_err(),
            AdmissionError::Scalar
        );
    }
    assert_eq!(
        extra("metadata: {true: x}").unwrap_err(),
        AdmissionError::Key
    );
    assert!(extra("metadata: {'true': x}").is_ok());
}

#[test]
fn rejects_duplicate_and_merge_keys() {
    for duplicate in [
        "title: other",
        "extra: {field: a, field: b}",
        r#"extra: {field: a, "fi\x65ld": b}"#,
    ] {
        assert_eq!(extra(duplicate).unwrap_err(), AdmissionError::DuplicateKey);
    }
    for merge in ["extra: {<<: {x: y}}", "extra: {'<<': {x: y}}"] {
        assert_eq!(extra(merge).unwrap_err(), AdmissionError::Merge);
    }
}

#[test]
fn rejects_anchors_aliases_and_tags() {
    for anchor in [
        "extra: &fixture value",
        "extra: &fixture [value]",
        "extra: &fixture {k: v}",
    ] {
        assert_eq!(extra(anchor).unwrap_err(), AdmissionError::Anchor);
    }
    assert!(extra("extra: *fixture").is_err());
    for tag in [
        "extra: !custom value",
        "extra: !!str 7",
        "extra: ! 7",
        "extra: !custom {k: v}",
    ] {
        assert_eq!(extra(tag).unwrap_err(), AdmissionError::Tag);
    }
}

#[test]
fn admits_one_utf8_document_without_bom_or_directives() {
    for bom in [
        format!("\u{feff}{RULE}"),
        format!("{RULE}extra: a\u{feff}b"),
    ] {
        assert_eq!(admit_rule(bom.as_bytes()).unwrap_err(), AdmissionError::Bom);
    }
    for directive in [
        "%YAML 1.2\n---\n",
        "%TAG !t! tag:fixture.invalid,2026:\r\n---\n",
    ] {
        assert_eq!(
            admit_rule(format!("{directive}{RULE}").as_bytes()).unwrap_err(),
            AdmissionError::Directive
        );
    }
    assert_eq!(
        admit_rule(&[0xff]).unwrap_err(),
        AdmissionError::InvalidUtf8
    );
    assert_eq!(
        extra(&format!("---\n{RULE}")).unwrap_err(),
        AdmissionError::Document
    );
    assert!(admit_rule(format!("---\n{RULE}...\n").as_bytes()).is_ok());
    assert!(extra("notes: |\n  %YAML is data\n").is_ok());
    assert!(admit_rule(b"").is_err());
    assert_eq!(
        extra("correlation: {type: event_count}").unwrap_err(),
        AdmissionError::RuleShape
    );
}

#[test]
fn bounds_bytes_scalars_depth_and_event_count() {
    assert_eq!(
        admit_rule(&vec![b' '; MAX_BYTES + 1]).unwrap_err(),
        AdmissionError::ByteLimit
    );
    assert_eq!(
        extra(&format!("data: '{}'", "a".repeat(MAX_SCALAR_BYTES + 1))).unwrap_err(),
        AdmissionError::Scalar
    );
    assert_eq!(
        extra(&format!(
            "extra: {}x{}",
            "[".repeat(MAX_DEPTH),
            "]".repeat(MAX_DEPTH)
        ))
        .unwrap_err(),
        AdmissionError::StructureLimit
    );
    assert_eq!(
        extra(&format!("extra: [{}x]", "x,".repeat(MAX_EVENTS))).unwrap_err(),
        AdmissionError::StructureLimit
    );
}
