//! Exercise every declared binding and measure the enrolled Parquet projections.
use super::{coverage_fixtures::*, *};
use crate::sigma_pack::field_table::{ReviewedSigmaFieldTable, SigmaConversion, SigmaFieldBinding};
use irmind_domain::{
    BoundedObservations, CategorySet, EventCategory, EventContextV1, EventHeaderV1, EventKind,
    EventOrigin, EventOutcome, EventText, EventTextList, EventType, EventTypeSet, EvidenceHash,
    IndexedTime,
};

fn all_variants() -> ReviewedSigmaFieldTable {
    parse_table(&crate::sigma_pack::runtime::enrolled_field_table().toml)
}

#[derive(Default)]
struct ProjectionInput {
    context: BTreeMap<CommonField, CommonValue>,
    categories: CategorySet,
    types: EventTypeSet,
    outcome: Option<EventOutcome>,
    action: Option<String>,
    code: Option<String>,
    dataset: Option<String>,
    id: Option<String>,
    original: serde_json::Map<String, Value>,
}

impl ProjectionInput {
    fn for_variant(variant: &SigmaSourceVariant) -> Self {
        let mut input = Self::default();
        for filter in &variant.events {
            let value = match &filter.values()[0] {
                SigmaLiteral::Text(value) => Value::from(value.clone()),
                SigmaLiteral::Integer(value) => Value::from(*value),
                SigmaLiteral::Boolean(value) => Value::from(*value),
            };
            if let Some(path) = &filter.path {
                input.insert_path(path, value);
            } else {
                input.set_column(filter.column.as_deref().unwrap(), &value);
            }
        }
        input
    }

    fn insert_path(&mut self, path: &[String], value: Value) {
        let (last, parents) = path.split_last().unwrap();
        let mut parent = &mut self.original;
        for part in parents {
            parent = parent
                .entry(part)
                .or_insert_with(|| Value::Object(serde_json::Map::new()))
                .as_object_mut()
                .unwrap();
        }
        parent.insert(last.clone(), value);
    }

    fn set_column(&mut self, column: &str, value: &Value) {
        match column {
            "event.category" => {
                self.categories =
                    CategorySet::new([EventCategory::parse(value.as_str().unwrap()).unwrap()]);
            }
            "event.type" => {
                self.types =
                    EventTypeSet::new([EventType::parse(value.as_str().unwrap()).unwrap()]);
            }
            "event.outcome" => {
                self.outcome = Some(EventOutcome::parse(value.as_str().unwrap()).unwrap());
            }
            "event.action" => self.action = Some(value.as_str().unwrap().into()),
            "event.code" => self.code = Some(value.as_str().unwrap().into()),
            "event.dataset" => self.dataset = Some(value.as_str().unwrap().into()),
            "event.id" => self.id = Some(value.as_str().unwrap().into()),
            column => {
                let field = CommonField::parse(column).unwrap();
                let value = match field.value_type() {
                    irmind_domain::CommonFieldType::Ip => {
                        CommonValue::Ip(value.as_str().unwrap().parse().unwrap())
                    }
                    irmind_domain::CommonFieldType::Boolean => {
                        CommonValue::Boolean(value.as_bool().unwrap())
                    }
                    irmind_domain::CommonFieldType::Text
                    | irmind_domain::CommonFieldType::LongText => {
                        CommonValue::Text(EventText::new(value.as_str().unwrap()).unwrap())
                    }
                    irmind_domain::CommonFieldType::TextList => CommonValue::TextList(
                        EventTextList::new(
                            value
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|item| EventText::new(item.as_str().unwrap()).unwrap())
                                .collect(),
                        )
                        .unwrap(),
                    ),
                    _ => CommonValue::Unsigned(value.as_u64().unwrap()),
                };
                self.context.insert(field, value);
            }
        }
    }

    fn binding(&mut self, binding: &SigmaFieldBinding, selected: Value) {
        if let Some(path) = &binding.path {
            if let Some(basename_path) = &binding.basename_path {
                let basename = selected
                    .as_str()
                    .unwrap()
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap();
                self.insert_path(basename_path, Value::from(basename));
            }
            self.insert_path(path, selected);
        } else {
            self.set_column(binding.column.as_deref().unwrap(), &selected);
        }
    }

    fn row(&self, variant: &SigmaSourceVariant, record: u64) -> CommonEventV1 {
        let mut context = EventContextV1::default();
        for (field, value) in &self.context {
            context.try_insert(*field, value.clone()).unwrap();
        }
        let mut header = EventHeaderV1::new(
            self.categories,
            self.types,
            self.outcome.unwrap_or(EventOutcome::Unknown),
            EventKind::Event,
        );
        if let Some(action) = &self.action {
            header = header.with_action(action).unwrap();
        }
        if let Some(code) = &self.code {
            header = header.with_code(code).unwrap();
        }
        if let Some(dataset) = &self.dataset {
            header = header.with_dataset(dataset).unwrap();
        }
        if let Some(id) = &self.id {
            header = header.with_id(id).unwrap();
        }
        CommonEventV1::try_new(
            EventOrigin::try_new(
                EvidenceHash::from_bytes([47; 32]),
                record,
                Some(50 + record),
                &variant.parser_id,
                &variant.parser_version,
            )
            .unwrap(),
            Some(IndexedTime::from_rfc3339("2026-11-01T01:02:03Z", false).unwrap()),
            header,
            context,
            BoundedObservations::default(),
        )
        .unwrap()
    }

    fn original(&self, variant: &SigmaSourceVariant, row: &CommonEventV1) -> String {
        if variant.exact_cluster_field().is_none() {
            return serde_json::to_string(&self.original).unwrap();
        }
        let common = irmind_app::encode_common_event(row).unwrap();
        let original = self
            .original
            .get("original")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let format = cluster_audit::FORMAT;
        format!(
            r#"{{"common":{common},"format":"{format}","original":{original},"unavailable":{{}}}}"#
        )
    }
}

fn sample(binding: &SigmaFieldBinding, hit: bool) -> Value {
    let text = if hit {
        "synthetic-match"
    } else {
        "synthetic-background"
    };
    if matches!(binding.conversion, Some(SigmaConversion::DefenderFullPath)) {
        return Value::from(format!("C:\\Synthetic\\{text}.exe"));
    }
    if matches!(
        binding.conversion,
        Some(SigmaConversion::EvtxEventId | SigmaConversion::EvtxLogonType)
    ) {
        return Value::from(if hit { "7" } else { "8" });
    }
    let number = if binding.name == "protoPayload.status.code" {
        if hit { 7 } else { 8 }
    } else if hit {
        402
    } else {
        403
    };
    let ip = if hit { "203.0.113.17" } else { "192.0.2.19" };
    match (binding.column.as_deref(), binding.value_type) {
        (Some("event.outcome"), _) => Value::from(if hit { "failure" } else { "success" }),
        (_, SigmaBindingType::Text) => Value::from(text),
        (_, SigmaBindingType::Ip) => Value::from(ip),
        (_, SigmaBindingType::Integer) => Value::from(number),
        (_, SigmaBindingType::Boolean) => Value::from(hit),
        (_, SigmaBindingType::TextList) => serde_json::json!([text]),
        (_, SigmaBindingType::IntegerList) => serde_json::json!([number]),
        (_, SigmaBindingType::IpList) => serde_json::json!([ip]),
        (_, SigmaBindingType::PairList) => {
            serde_json::json!([{ "Name": "Synthetic", "Value": text }])
        }
    }
}

fn condition(variant: &SigmaSourceVariant) -> String {
    let clauses = [
        ("product", &variant.product),
        ("service", &variant.service),
        ("category", &variant.category),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}: {value}")))
    .collect::<Vec<_>>();
    format!("{{{}}}", clauses.join(", "))
}

fn binding_selection(binding: &SigmaFieldBinding, value: &Value) -> String {
    if matches!(
        binding.conversion,
        Some(SigmaConversion::EvtxEventId | SigmaConversion::EvtxLogonType)
    ) {
        return format!(
            r#"{{"{}": {}}}"#,
            binding.name,
            value.as_str().unwrap().parse::<u16>().unwrap()
        );
    }
    selection(&binding.name, value)
}

fn selection(name: &str, value: &Value) -> String {
    if value
        .as_str()
        .is_some_and(|text| text.parse::<std::net::IpAddr>().is_ok())
    {
        let address = value.as_str().unwrap();
        return format!(r#"{{"{name}|cidr": "{address}/32"}}"#);
    }
    if let Some(values) = value.as_array() {
        return selection(name, &values[0]);
    }
    format!(r#"{{"{name}": {value}}}"#)
}

fn selector_value(variant: &SigmaSourceVariant, binding: &SigmaFieldBinding) -> Option<Value> {
    let selected = variant
        .events
        .iter()
        .find(|event| event.column == binding.column && event.path == binding.path)?;
    Some(match &selected.values()[0] {
        SigmaLiteral::Text(value) => Value::from(value.clone()),
        SigmaLiteral::Integer(value) => Value::from(*value),
        SigmaLiteral::Boolean(value) => Value::from(*value),
    })
}

#[test]
fn sigma_every_enrolled_binding_matches_and_rejects_a_negative_control() {
    let table = all_variants();
    for variant in &table.variants {
        let taxonomy = condition(variant);
        for binding in &variant.fields {
            let mut source = ProjectionInput::for_variant(variant);
            let value = selector_value(variant, binding).unwrap_or_else(|| sample(binding, true));
            source.binding(binding, value.clone());
            let row = source.row(variant, 0);
            let raw = source.original(variant, &row);
            let positive = binding_selection(binding, &value);
            let negative = binding_selection(binding, &sample(binding, false));
            assert_eq!(
                evaluate(variant, &taxonomy, &positive, &row, Some(&raw)),
                (1, None),
                "{} {}",
                taxonomy,
                binding.name
            );
            assert_eq!(
                evaluate(variant, &taxonomy, &negative, &row, Some(&raw)),
                (0, None),
                "{} {}",
                taxonomy,
                binding.name
            );
        }
    }
}

#[test]
#[cfg(not(debug_assertions))]
#[ignore = "release benchmark of all Sigma classes on at least 1 GiB of synthetic Parquet"]
fn sigma_reviewed_families_2000_rules_on_one_gib_parquet() {
    let table = all_variants();
    let families = table.variants.len() as u64;
    let padded = table
        .variants
        .iter()
        .filter(|variant| variant.exact_cluster_field().is_none())
        .count() as u64;
    let rows = (1024 * 1024 * 1024u64).div_ceil(padded * 4096);
    let directory = tempfile::tempdir().unwrap();
    let mut remaining = 2000;
    let mut corpus_bytes = 0;
    for (ordinal, variant) in table.variants.iter().enumerate() {
        let count = remaining / (table.variants.len() - ordinal);
        remaining -= count;
        corpus_bytes += measure_variant(
            variant,
            count,
            rows,
            &directory.path().join("family.parquet"),
        );
    }
    assert_eq!(remaining, 0);
    assert!(corpus_bytes >= 1024 * 1024 * 1024);
    println!("classes={families} total_rules=2000 parquet_bytes={corpus_bytes}");
}

#[cfg(not(debug_assertions))]
const UNMAPPED_TEST_FIELD: &str = "__synthetic_unmapped_field";

#[cfg(not(debug_assertions))]
fn measure_variant(
    variant: &SigmaSourceVariant,
    count: usize,
    rows: u64,
    file: &std::path::Path,
) -> u64 {
    use std::{
        fs::File,
        time::{Duration, Instant},
    };
    let binding = variant
        .fields
        .iter()
        .find(|binding| selector_value(variant, binding).is_none())
        .unwrap();
    write_family_fixture(variant, binding, rows, file);
    let taxonomy = condition(variant);
    let rules = measure_rules(&taxonomy, binding, count);
    let start = Instant::now();
    let plans = SigmaVariantPrograms::compile(
        variant,
        rules
            .iter()
            .map(|(key, bytes)| (key.clone(), bytes.as_bytes())),
    )
    .unwrap();
    let compile_seconds = start.elapsed().as_secs_f64();
    let reason = assert_control_omission(variant, &taxonomy, &plans, &rules.last().unwrap().0);
    let start = Instant::now();
    let file_reader = File::open(file).unwrap();
    let bytes = file_reader.metadata().unwrap().len();
    let mut run = plans.start(8_000_000_000);
    let mut true_positives = 0;
    let mut false_positives = 0;
    run.scan_authenticated(
        file_reader,
        0..i64::MAX,
        start + Duration::from_mins(3),
        &CancellationToken::new(),
        |row, _, rule| {
            if row == 0 && rule.id == "synthetic-0000" {
                true_positives += 1;
            } else {
                false_positives += 1;
            }
            Ok(())
        },
    )
    .unwrap();
    let scan_seconds = start.elapsed().as_secs_f64();
    assert_eq!(run.status(), SigmaRunStatusV1::Complete);
    assert_eq!(
        (true_positives, false_positives, run.rules_evaluated()),
        (1, 0, count - 1),
        "{taxonomy} {}",
        binding.name
    );
    println!(
        "source={taxonomy} class={} scope={} field={} lane={} parquet_bytes={bytes} rows={rows} rules={count} evaluated={} skipped={} skipped_reason={reason:?} expected=1 tp={true_positives} fp={false_positives} compile_s={compile_seconds:.6} scan_s={scan_seconds:.6}",
        variant
            .dataset
            .as_deref()
            .or(variant.channel.as_deref())
            .unwrap(),
        variant.mapping_id,
        binding.name,
        if binding.path.is_some() {
            "original"
        } else {
            "common"
        },
        run.rules_evaluated(),
        plans.skipped().len()
    );
    std::fs::remove_file(file).unwrap();
    bytes
}

#[cfg(not(debug_assertions))]
fn assert_control_omission(
    variant: &SigmaSourceVariant,
    taxonomy: &str,
    plans: &SigmaVariantPrograms,
    control: &SigmaRuleKeyV1,
) -> SigmaCoverageV1 {
    assert!(
        variant
            .fields
            .iter()
            .all(|field| field.name != UNMAPPED_TEST_FIELD),
        "{taxonomy} declares the reserved benchmark negative-control field"
    );
    let expected = (control.clone(), SigmaCoverageV1::UnsupportedField);
    assert_eq!(plans.skipped().len(), 1, "{taxonomy}");
    assert!(
        plans.skipped()[0] == expected,
        "{taxonomy} must omit only the synthetic negative control"
    );
    plans.skipped()[0].1
}

#[cfg(not(debug_assertions))]
fn write_family_fixture(
    variant: &SigmaSourceVariant,
    binding: &SigmaFieldBinding,
    rows: u64,
    file: &std::path::Path,
) {
    use irmind_app::encode_common_event;

    let mut incident = ProjectionInput::for_variant(variant);
    let mut background = ProjectionInput::for_variant(variant);
    incident.binding(binding, sample(binding, true));
    background.binding(binding, sample(binding, false));
    if variant.exact_cluster_field().is_none() {
        for input in [&mut incident, &mut background] {
            input
                .original
                .insert("synthetic_padding".into(), Value::from("x".repeat(4096)));
        }
    }
    benchmark::write_fixture_rows(file, rows, |row| {
        let input = if row == 0 { &incident } else { &background };
        let row = input.row(variant, row);
        (
            encode_common_event(&row).unwrap(),
            input.original(variant, &row),
        )
    });
}

#[cfg(not(debug_assertions))]
fn measure_rules(
    taxonomy: &str,
    binding: &SigmaFieldBinding,
    count: usize,
) -> Vec<(SigmaRuleKeyV1, String)> {
    (0..count).map(|index| {
        let name = if index + 1 == count { UNMAPPED_TEST_FIELD } else { binding.name.as_str() };
        let predicate = if index == 0 {
            binding_selection(binding, &sample(binding, true))
        } else if name == binding.name && binding.value_type == SigmaBindingType::PairList {
            format!(r#"{{"{name}": {{"Name": "Synthetic", "Value": "unmatched-{index}"}}}}"#)
        } else {
            format!(r#"{{"{name}|exists": false}}"#)
        };
        let bytes = format!("title: Synthetic measured rule {index}\nlogsource: {taxonomy}\ndetection: {{selection: {predicate}, condition: selection}}\n");
        let key = SigmaRuleKeyV1 { id: format!("synthetic-{index:04}"), sha256: irmind_app::sha256(bytes.as_bytes()) };
        (key, bytes)
    }).collect()
}
