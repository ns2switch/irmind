use super::tests::{mapper, source};
use super::*;
use irmind_app::source_mapping::{SourceNumber, SourceValue};
use irmind_domain::{CommonField, EntityRole, EventOutcome};
use std::fmt::Write as _;
const BASE: &str = include_str!("../tests/fixtures/synthetic-status.toml");
fn definition(values: &[String]) -> String {
    format!(
        "interpreter = \"irmind-mapping-tables-v2\"\n{}",
        BASE.replacen(
            "conversion = \"ip\"",
            &format!(
                "conversion = \"ip\"\nomit_text = {}",
                serde_json::to_string(values).unwrap()
            ),
            1
        )
    )
}
fn record(client: Option<SourceValue>) -> SourceRecordV1 {
    let mut fields = vec![
        ("status".into(), SourceValue::Text("failed".into())),
        ("server".into(), SourceValue::Text("203.0.113.7".into())),
    ];
    if let Some(value) = client {
        fields.push(("client".into(), value));
    }
    source(SourceValue::object(fields).unwrap())
}
fn bytes(record: &SourceRecordV1) -> Vec<u8> {
    let mut value = Vec::new();
    record.feed_canonical(&mut |part| value.extend_from_slice(part));
    value
}
#[test]
fn omission_preserves_original_bytes_classification_and_other_observations() {
    let mapper = mapper(&definition(&[String::new(), "-".into()]));
    let mut encodings = std::collections::BTreeSet::new();
    for client in [
        None,
        Some(SourceValue::Null),
        Some(SourceValue::Text(String::new())),
        Some(SourceValue::Text("-".into())),
    ] {
        let source = record(client);
        let original = bytes(&source);
        let output = mapper.map(&source).unwrap();
        assert_eq!(
            output.record().common.event().outcome(),
            EventOutcome::Failure
        );
        assert!(
            output
                .record()
                .common
                .context()
                .get(CommonField::SourceIp)
                .is_none()
        );
        let observed = output.record().common.observations().values();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].role(), EntityRole::Destination);
        assert_eq!(bytes(&source), original);
        encodings.insert(original);
    }
    assert_eq!(encodings.len(), 4);
    let source = record(Some(SourceValue::Text("203.0.113.7".into())));
    let output = mapper.map(&source).unwrap();
    let observed = output.record().common.observations().values();
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].entity(), observed[1].entity());
    assert_ne!(observed[0].role(), observed[1].role());
}
#[test]
fn unlisted_invalid_values_and_nontext_values_still_fail_conversion() {
    let mapper = mapper(&definition(&["NONE".into(), "0".into()]));
    for client in [
        SourceValue::Text("none".into()),
        SourceValue::Text("not-an-ip".into()),
        SourceValue::Number(SourceNumber::try_new("0").unwrap()),
        SourceValue::Boolean(false),
    ] {
        assert!(mapper.map(&record(Some(client))).is_err());
    }
    let catalog = irmind_app::source_mapping::MappingCatalog::freeze(
        vec![std::sync::Arc::new(
            irmind_mod_parser_json::JsonSourceDecoder,
        )],
        vec![std::sync::Arc::new(mapper)],
    )
    .unwrap();
    let (_, output) = catalog
        .map(&record(Some(SourceValue::Text("not-an-ip".into()))))
        .unwrap();
    assert_eq!(output.record().common.event().categories().bits(), 0);
    assert_eq!(
        output.record().common.event().outcome(),
        EventOutcome::Unknown
    );
    assert!(!output.diagnostics().is_empty());
}
#[test]
fn finite_lists_reject_duplicates_controls_and_utf8_byte_overflow() {
    for values in [
        vec!["-".into(), "-".into()],
        (0..9).map(|i| i.to_string()).collect(),
        vec!["a".repeat(257)],
        vec!["é".repeat(129)],
        vec!["\n".into()],
        vec!["\u{1b}".into()],
        vec!["\u{85}".into()],
    ] {
        assert!(TableMapping::review(&definition(&values)).is_err());
    }
    for values in [
        vec!["a".repeat(256)],
        vec!["é".repeat(128)],
        (0..8).map(|i| i.to_string()).collect(),
    ] {
        assert!(TableMapping::review(&definition(&values)).is_ok());
    }
}
#[test]
fn no_unicode_folding_or_implicit_zero_pid_omission() {
    let text = format!(
        "interpreter = \"irmind-mapping-tables-v2\"\n{BASE}\n[[fields]]\nsource = [\"actor\"]\ntarget = \"user.name\"\nomit_text = [\"é\"]\n[[fields]]\nsource = [\"pid\"]\ntarget = \"process.pid\"\nomit_text = [\"\"]\n"
    );
    let mapper = mapper(&text);
    for (actor, present) in [("é", false), ("e\u{301}", true)] {
        let source = source(
            SourceValue::object(vec![
                ("actor".into(), SourceValue::Text(actor.into())),
                (
                    "pid".into(),
                    SourceValue::Number(SourceNumber::try_new("0").unwrap()),
                ),
            ])
            .unwrap(),
        );
        let output = mapper.map(&source).unwrap();
        assert_eq!(
            output
                .record()
                .common
                .context()
                .get(CommonField::UserName)
                .is_some(),
            present
        );
        assert!(
            output
                .record()
                .common
                .context()
                .get(CommonField::ProcessPid)
                .is_some()
        );
    }
}
#[test]
fn omitted_pam_actor_keeps_the_target_and_two_present_roles_remain_distinct() {
    let text = format!(
        "interpreter = \"irmind-mapping-tables-v2\"\n{BASE}\n[[fields]]\nsource=[\"logname\"]\ntarget=\"user.name\"\nomit_text=[\"\"]\nobservation={{kind=\"user\",role=\"actor\"}}\n[[fields]]\nsource=[\"target\"]\ntarget=\"user.target.name\"\nobservation={{kind=\"user\",role=\"target\"}}\n"
    );
    let mapper = mapper(&text);
    for name in ["", "alice"] {
        let source = source(
            SourceValue::object(vec![
                ("logname".into(), SourceValue::Text(name.into())),
                ("target".into(), SourceValue::Text("alice".into())),
            ])
            .unwrap(),
        );
        let output = mapper.map(&source).unwrap();
        let obs = output.record().common.observations().values();
        assert_eq!(obs.len(), if name.is_empty() { 1 } else { 2 });
        assert!(obs.iter().any(|o| o.role() == EntityRole::Target));
        if !name.is_empty() {
            assert_eq!(obs[0].entity(), obs[1].entity());
        }
    }
}
#[test]
fn current_interpreter_identity_and_empty_list_canonical_bytes_stay_fixed() {
    let absent =
        TableMapping::review(&format!("interpreter=\"irmind-mapping-tables-v2\"\n{BASE}")).unwrap();
    let empty = TableMapping::review(&definition(&[])).unwrap();
    assert_eq!(absent, empty);
    let listed = TableMapping::review(&definition(&["-".into()])).unwrap();
    assert_ne!(
        absent.identity().implementation(),
        listed.identity().implementation()
    );
    assert!(
        matches!(listed.provenance(),irmind_app::source_mapping::MappingProvenance::BundledDefinition{interpreter,..} if interpreter=="irmind-mapping-tables-v2")
    );
}
#[test]
fn literal_comparisons_count_toward_the_existing_operation_budget() {
    let header = BASE.split("[[rules]]").next().unwrap();
    let mut text = format!("interpreter=\"irmind-mapping-tables-v2\"\n{header}");
    for i in 0..100 {
        write!(text, "\n[[rules]]\n[[rules.when]]\npath=[\"status\"]\npredicate={{op=\"text\",value=\"{i}\"}}\n").unwrap();
        for target in ["source.ip", "destination.ip"] {
            write!(text, "[[rules.fields]]\nsource=[\"ip\"]\ntarget=\"{target}\"\nconversion=\"ip\"\nomit_text=[\"0\",\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\"]\n").unwrap();
        }
    }
    let definition: crate::definition::Definition = toml::from_str(&text).unwrap();
    assert!(serde_json::to_vec(&definition).unwrap().len() <= 64 * 1024);
    assert!(TableMapping::review(&text).is_err());
}

#[test]
fn omission_does_not_suppress_unlisted_port_or_hash_validation_errors() {
    for (field, conversion, value) in [
        (
            "source.port",
            "copy",
            SourceValue::Number(SourceNumber::try_new("65536").unwrap()),
        ),
        (
            "process.hash.sha256",
            "sha256",
            SourceValue::Text("not-a-hash".into()),
        ),
    ] {
        let definition = format!(
            "interpreter = \"irmind-mapping-tables-v2\"\n{BASE}\n[[fields]]\nsource=[\"extra\"]\ntarget=\"{field}\"\nconversion=\"{conversion}\"\nomit_text=[\"-\"]\n"
        );
        let source = source(SourceValue::object(vec![("extra".into(), value)]).unwrap());
        assert!(mapper(&definition).map(&source).is_err());
    }
}
