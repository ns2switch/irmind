use super::{
    TableMapping,
    tests::{mapper, source},
};
use irmind_app::{SourceMapper, source_mapping::SourceValue};
use irmind_domain::EntityIdentityScope;
const DEF: &str = r#"interpreter = "irmind-mapping-tables-v2"
id = "mapping-synthetic-lifetime"
version = "1"
target_schema = "irmind-common-event-v1"
source_contract = "irmind-source-record-v1"
parser = "parser-json"
parser_versions = ["json-source-v1"]
[[fields]]
source = ["pid"]
target = "process.pid"
conversion = "decimal"
observation = { kind = "process", role = "subject", scope = { kind = "process_lifetime", path = { host = ["host"], lifetime = ["ProcessGuid"] } } }
"#;
fn record(
    host: SourceValue,
    lifetime: Option<SourceValue>,
) -> irmind_app::source_mapping::SourceRecordV1 {
    let mut fields = vec![
        ("pid".into(), SourceValue::Text("42".into())),
        ("host".into(), host),
    ];
    if let Some(value) = lifetime {
        fields.push(("ProcessGuid".into(), value));
    }
    source(SourceValue::object(fields).unwrap())
}
#[test]
fn explicit_reported_lifetime_is_stable_and_pid_reuse_does_not_join() {
    let mapping = mapper(DEF);
    let host = SourceValue::Text("synthetic-host".into());
    let a = mapping
        .map(&record(
            host.clone(),
            Some(SourceValue::Text("guid-a".into())),
        ))
        .unwrap();
    let b = mapping
        .map(&record(
            host.clone(),
            Some(SourceValue::Text("guid-a".into())),
        ))
        .unwrap();
    let c = mapping
        .map(&record(host, Some(SourceValue::Text("guid-b".into()))))
        .unwrap();
    let entity = |out: &irmind_app::source_mapping::MappingOutput| {
        out.record().common.observations().values()[0]
            .entity()
            .clone()
    };
    assert_eq!(entity(&a), entity(&b));
    assert_ne!(entity(&a), entity(&c));
    assert!(matches!(
        entity(&a).scope(),
        EntityIdentityScope::ProcessLifetime { .. }
    ));
}
#[test]
fn missing_null_wrong_type_and_invalid_identifiers_never_fall_back() {
    let mapping = mapper(DEF);
    for lifetime in [
        None,
        Some(SourceValue::Null),
        Some(SourceValue::Boolean(true)),
        Some(SourceValue::Text(String::new())),
        Some(SourceValue::Text("bad\nvalue".into())),
    ] {
        assert!(
            mapping
                .map(&record(SourceValue::Text("host".into()), lifetime))
                .is_err()
        );
    }
    assert!(
        mapping
            .map(&record(
                SourceValue::Boolean(true),
                Some(SourceValue::Text("guid".into()))
            ))
            .is_err()
    );
    assert!(TableMapping::review(&DEF.replace(r#"kind = "process""#, r#"kind = "user""#)).is_err());
}
