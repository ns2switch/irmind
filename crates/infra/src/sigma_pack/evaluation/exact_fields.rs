use super::{coverage_fixtures::parse_table, *};
use crate::sigma_pack::field_table::ReviewedSigmaFieldTable;
use irmind_app::v10_proofs::SigmaFieldTableV1;

const VECTOR: &str =
    include_str!("../../../../testkit/fixtures/contracts/sigma_exact_source_fields.json");
const TABLE: &str =
    include_str!("../../../../testkit/fixtures/contracts/sigma_exact_source_fields.toml");

fn vector_bundle() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

#[test]
fn unavailable_rows_are_indeterminate_for_positive_negated_and_presence_predicates() {
    let mut variant = parse_table(TABLE).variants.into_iter().nth(3).unwrap();
    variant.fields.push(
        toml::from_str(
            r#"
name = "Verb"
column = "event.action"
value_type = "text"
null_policy = "absent"
"#,
        )
        .unwrap(),
    );
    let rules = cluster_rules();
    let programs = SigmaVariantPrograms::compile(
        &variant,
        rules.iter().map(|(id, raw)| {
            (
                SigmaRuleKeyV1 {
                    id: (*id).into(),
                    sha256: irmind_app::sha256(raw.as_bytes()),
                },
                raw.as_bytes(),
            )
        }),
    )
    .unwrap();
    assert_eq!(programs.skipped().len(), 0);
    let mut run = programs.start(100_000);
    let bundle = vector_bundle();
    let projections = bundle["retained_text"].as_array().unwrap();
    for (label, matches) in [
        ("xff_33_ips", vec!["common"]),
        ("invalid_first_ip", vec!["common"]),
        ("native", vec!["positive", "negative", "common"]),
        ("missing_list", vec!["negative", "absent", "common"]),
        ("explicit_empty_list", vec!["negative", "common"]),
    ] {
        let vector = projections
            .iter()
            .find(|item| item["case"] == label)
            .unwrap();
        let retained = &vector["retained"];
        let common = irmind_app::decode_common_event(&retained["common"].to_string()).unwrap();
        let mut seen = Vec::new();
        assert!(
            run.row(
                &common,
                Some(&retained.to_string()),
                &CancellationToken::new(),
                |key| {
                    seen.push(key.id.clone());
                    Ok(())
                }
            )
            .unwrap()
        );
        assert_eq!(seen, matches, "{label}");
    }
    assert_eq!(
        run.unavailable_by_source
            .values()
            .copied()
            .collect::<Vec<_>>(),
        [2]
    );
    assert_eq!(run.indeterminate_by_rule.len(), 3);
    assert!(run.indeterminate_by_rule.values().all(|count| *count == 2));
}

fn cluster_rules() -> Vec<(&'static str, String)> {
    let selections = [
        ("positive", "'sourceIPs|cidr': 203.0.113.0/24", "select"),
        (
            "negative",
            "'sourceIPs|cidr': 198.51.100.0/24",
            "not select",
        ),
        ("absent", "'sourceIPs|exists': false", "select"),
    ];
    let mut rules = selections.into_iter().map(|(id, terms, condition)| {
        let text = format!(
            "title: Synthetic IP test\nlogsource: {{product: kubernetes, service: audit}}\ndetection:\n  select: {{{terms}}}\n  condition: '{condition}'\n"
        );
        (id, text)
    }).collect::<Vec<_>>();
    rules.push((
        "common",
        "title: Synthetic action\nlogsource: {product: kubernetes, service: audit}\ndetection: {selection: {Verb: get}, condition: selection}\n".into(),
    ));
    rules
}

#[test]
fn exact_defender_evtx_and_m365_bindings_use_the_approved_vectors() {
    let table = ReviewedSigmaFieldTable::parse(&SigmaFieldTableV1 {
        id: "exact-fixtures".into(),
        version: "v2".into(),
        toml: TABLE.into(),
    })
    .unwrap();
    let bundle = vector_bundle();
    for vector in bundle["defender_bindings"].as_array().unwrap() {
        let variant = &table.variants[2];
        let row =
            coverage_fixtures::synthetic_row(variant, irmind_domain::EventHeaderV1::default(), []);
        let projection = project_fields(
            variant,
            &BTreeSet::from(["Image", "ParentImage"]),
            &row,
            Some(&vector["source"]),
        )
        .unwrap();
        for (name, field) in projection {
            match field.view() {
                SigmaField::Absent => assert!(vector["expected"].get(name).is_none()),
                SigmaField::Single(SigmaScalar::Text(path)) => {
                    assert_eq!(path, vector["expected"][name]);
                }
                _ => unreachable!("unexpected Defender value"),
            }
        }
    }

    let value = &bundle["evtx_bindings"][0]["source"];
    assert!(matches!(
        evtx_number(&value["EventID"], 5, u16::MAX).unwrap(),
        Projection::Single(SigmaScalar::Integer(4625))
    ));
    assert!(matches!(
        evtx_number(&value["LogonType"], 3, u16::from(u8::MAX)).unwrap(),
        Projection::Single(SigmaScalar::Integer(3))
    ));
    let value = &bundle["evtx_bindings"][1]["source"];
    assert!(evtx_number(&value["EventID"], 5, u16::MAX).is_err());
    assert!(evtx_number(&value["LogonType"], 3, u16::from(u8::MAX)).is_err());

    let exchange = &table.variants[1];
    let row =
        coverage_fixtures::synthetic_row(exchange, irmind_domain::EventHeaderV1::default(), []);
    let mut original = bundle["m365_pairs"]["source"].clone();
    original["Workload"] = Value::from("Exchange");
    for (key, hits) in [("matches", 1), ("does_not_match", 0)] {
        let predicate = format!("{{Parameters: {}}}", bundle["m365_pairs"][key]);
        assert_eq!(
            coverage_fixtures::evaluate(
                exchange,
                "{product: m365, service: exchange}",
                &predicate,
                &row,
                Some(&original.to_string()),
            ),
            (hits, None)
        );
    }
}
