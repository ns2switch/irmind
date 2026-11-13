use irmind_app::common_event::*;
use irmind_domain::{EvidenceHash, IndexedInstant, IndexedTime, TimePrecision};
use serde_json::Value;
use std::collections::BTreeMap;

#[test]
fn all_closed_field_types_round_trip_with_lexical_keys_in_both_map_modes() {
    let base = irmind_app::decode_common_event(
        include_str!("../../../app/src/common_event/goldens/network-v1.json").trim(),
    )
    .unwrap();
    let mut context = EventContextV1::default();
    for field in CommonField::all() {
        context
            .try_insert(
                field,
                if field == CommonField::IrmindClusterIdentity {
                    CommonValue::Text(EventText::new("kubernetes:urn:k8s:synthetic").unwrap())
                } else {
                    value_for(field.value_type())
                },
            )
            .unwrap();
    }
    let event = CommonEventV1::try_new(
        base.origin().clone(),
        base.timestamp(),
        base.event()
            .clone()
            .with_code("synthetic")
            .unwrap()
            .with_id("event-7")
            .unwrap()
            .with_dataset("synthetic.events")
            .unwrap(),
        context,
        BoundedObservations::default(),
    )
    .unwrap();
    let encoded = irmind_app::encode_common_event(&event).unwrap();
    let parsed: Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        parsed["context"].as_object().unwrap().len(),
        CommonField::ALL.len()
    );
    assert_eq!(encoded, serde_json::to_string(&lexical(parsed)).unwrap());
    assert_eq!(irmind_app::decode_common_event(&encoded).unwrap(), event);
}

fn value_for(kind: CommonFieldType) -> CommonValue {
    use CommonFieldType as T;
    match kind {
        T::Boolean => CommonValue::Boolean(true),
        T::Text | T::LongText => CommonValue::Text(EventText::new("synthetic").unwrap()),
        T::Ip => CommonValue::Ip("2001:db8::77".parse().unwrap()),
        T::Unsigned | T::Port | T::Pid => CommonValue::Unsigned(443),
        T::HttpStatus => CommonValue::Unsigned(200),
        T::Md5 | T::Sha1 | T::Sha256 => {
            let (algorithm, size) = match kind {
                T::Md5 => (HashAlgorithm::Md5, 16),
                T::Sha1 => (HashAlgorithm::Sha1, 20),
                _ => (HashAlgorithm::Sha256, 32),
            };
            CommonValue::Hash(ContentHash::new(algorithm, &"ab".repeat(size)).unwrap())
        }
        T::Time => CommonValue::Time(
            IndexedTime::new(
                IndexedInstant::new(-1, 789).unwrap(),
                TimePrecision::Unknown,
                true,
            )
            .unwrap(),
        ),
        T::Direction => CommonValue::Direction(NetworkDirection::Outbound),
        T::TextList => CommonValue::TextList(
            EventTextList::new(vec![EventText::new("synthetic").unwrap()]).unwrap(),
        ),
        T::DnsAnswers => CommonValue::DnsAnswers(
            DnsAnswers::new(vec![
                DnsAnswer::new(
                    EventText::new("example.test").unwrap(),
                    EventText::new("AAAA").unwrap(),
                    EventText::new("2001:db8::77").unwrap(),
                )
                .unwrap(),
            ])
            .unwrap(),
        ),
    }
}

fn lexical(value: Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, lexical(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(lexical).collect()),
        value => value,
    }
}

#[test]
fn every_identity_scope_keeps_its_canonical_bytes() {
    let hash = EvidenceHash::parse(&"ab".repeat(32)).unwrap();
    let text = |value| EventText::identifier(value).unwrap();
    let cases = [
        (
            EntityIdentityScope::cluster(irmind_domain::ClusterIdentity::try_new(irmind_domain::ClusterProvider::Kubernetes, "urn:k8s:lab").unwrap(), Some("production")).unwrap(),
            r#"{"id":"urn:k8s:lab","kind":"cluster","namespace":"production","provider":"kubernetes"}"#.into(),
        ),
        (
            EntityIdentityScope::Global,
            r#"{"kind":"global"}"#.to_owned(),
        ),
        (
            EntityIdentityScope::Account(text("account")),
            r#"{"kind":"account","value":"account"}"#.into(),
        ),
        (
            EntityIdentityScope::Host(text("host")),
            r#"{"kind":"host","value":"host"}"#.into(),
        ),
        (
            EntityIdentityScope::SourceRecord {
                source: hash.clone(),
                record: 7,
            },
            format!(
                r#"{{"kind":"source_record","record":7,"source":"{}"}}"#,
                hash.as_str()
            ),
        ),
        (
            EntityIdentityScope::ProcessLifetime {
                host: text("host"),
                lifetime: text("lifetime"),
            },
            r#"{"host":"host","kind":"process_lifetime","lifetime":"lifetime"}"#.into(),
        ),
    ];
    for (scope, expected) in cases {
        assert_eq!(encode_identity_scope(&scope).unwrap(), expected);
        assert_eq!(decode_identity_scope(&expected).unwrap(), scope);
    }
}
