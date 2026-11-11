use super::*;
use irmind_app::{
    SourceDecoder,
    source_mapping::{DecodeAnnotationsV1, SourceFormatV1, SourceValue},
};
use irmind_domain::{COMMON_EVENT_V1, EntityRole, EventOrigin, EventOutcome, EvidenceHash};
use std::{collections::BTreeMap, sync::Arc};
const DEFINITION: &str = include_str!("../tests/fixtures/synthetic-status.toml");
pub(super) fn mapper(text: &str) -> TableMapping {
    let manifest = TableMapping::review(text).unwrap();
    TableMapping::bundled(text, manifest.identity().implementation()).unwrap()
}
pub(super) fn source(fields: SourceValue) -> SourceRecordV1 {
    SourceRecordV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([4; 32]),
            0,
            None,
            "parser-json",
            "json-source-v1",
        )
        .unwrap(),
        "synthetic.json",
        None,
        SourceFormatV1::try_new("json", "source-json-v1", BTreeMap::new()).unwrap(),
        fields,
        DecodeAnnotationsV1::default(),
    )
    .unwrap()
}
#[test]
fn finite_statuses_preserve_same_value_in_two_roles_and_missing_is_unknown() {
    let mapper = mapper(DEFINITION);
    for (status, outcome) in [
        (Some("failed"), EventOutcome::Failure),
        (Some("accepted"), EventOutcome::Success),
        (Some("unrecognized"), EventOutcome::Unknown),
        (None, EventOutcome::Unknown),
    ] {
        let mut fields = vec![
            ("client".into(), SourceValue::Text("203.0.113.7".into())),
            ("server".into(), SourceValue::Text("203.0.113.7".into())),
        ];
        if let Some(status) = status {
            fields.push(("status".into(), SourceValue::Text(status.into())));
        }
        let source = source(SourceValue::object(fields).unwrap());
        let output = mapper.map(&source).unwrap();
        assert_eq!(output.record().common.event().outcome(), outcome);
        let observations = output.record().common.observations().values();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].entity(), observations[1].entity());
        assert_ne!(observations[0].role(), observations[1].role());
        assert!(observations.iter().any(|o| o.role() == EntityRole::Source));
        assert_eq!(output.record().common.origin(), source.origin());
    }
}
#[test]
fn definitions_are_bounded_closed_and_cannot_smuggle_expressions_or_roles() {
    for invalid in [
        DEFINITION.replace("role = \"source\"", "role = \"actor\""),
        DEFINITION.replace("conversion = \"ip\"", "conversion = \"shell\""),
        DEFINITION.replace("value = \"accepted\"", "value = \"failed\""),
        format!("{DEFINITION}\nunknown = 1"),
        DEFINITION.repeat(300),
    ] {
        assert!(TableMapping::review(&invalid).is_err());
    }
    assert!(TableMapping::bundled(DEFINITION, &EvidenceHash::from_bytes([0; 32])).is_err());
    assert!(!format!("{:?}", mapper(DEFINITION)).contains("failed"));
}
#[test]
fn shared_contract_checks_purity_parallelism_taint_and_cancellation() {
    let decoder: Arc<dyn SourceDecoder> = Arc::new(irmind_mod_parser_json::JsonSourceDecoder);
    let mapper: Arc<dyn SourceMapper> = Arc::new(mapper(DEFINITION));
    let fixture = br#"{"eventTime":"2026-11-01T00:00:00Z","status":"failed","client":"203.0.113.7","server":"203.0.113.8"}"#;
    irmind_testkit::run_source_mapping_contract(decoder, mapper, "synthetic.json", fixture, 1)
        .unwrap();
}
#[test]
fn canonical_definition_is_map_order_independent_and_pin_is_unchanged() {
    let first = TableMapping::review(DEFINITION).unwrap();
    let second = TableMapping::review(&DEFINITION.replace(
        "version = \"1\"\ntarget_schema = \"irmind-common-event-v1\"",
        "target_schema = \"irmind-common-event-v1\"\nversion = \"1\"",
    ))
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.identity().target(), COMMON_EVENT_V1);
}

#[test]
fn native_constructor_and_declarative_rule_produce_identical_canonical_events() {
    use irmind_domain::{
        BoundedObservations, CategorySet, CommonEventV1, CommonField, CommonValue,
        EntityIdentityScope, EntityObservation, EventCategory, EventContextV1, EventHeaderV1,
        EventKind, EventType, EventTypeSet, ObservedEntity, ObservedEntityKind,
    };
    let source = source(
        SourceValue::object(vec![
            ("status".into(), SourceValue::Text("failed".into())),
            ("client".into(), SourceValue::Text("203.0.113.7".into())),
            ("server".into(), SourceValue::Text("203.0.113.8".into())),
        ])
        .unwrap(),
    );
    let mut context = EventContextV1::default();
    let mut observations = vec![];
    for (field, role, address) in [
        (CommonField::SourceIp, EntityRole::Source, "203.0.113.7"),
        (
            CommonField::DestinationIp,
            EntityRole::Destination,
            "203.0.113.8",
        ),
    ] {
        context
            .try_insert(field, CommonValue::Ip(address.parse().unwrap()))
            .unwrap();
        observations.push(
            EntityObservation::try_new(
                ObservedEntity::try_new(
                    ObservedEntityKind::Ip,
                    address,
                    EntityIdentityScope::Global,
                )
                .unwrap(),
                role,
                field,
            )
            .unwrap(),
        );
    }
    let native = CommonEventV1::try_new(
        source.origin().clone(),
        source.timestamp(),
        EventHeaderV1::new(
            CategorySet::new([EventCategory::Authentication]),
            EventTypeSet::new([EventType::Start]),
            EventOutcome::Failure,
            EventKind::Event,
        ),
        context,
        BoundedObservations::try_new(observations).unwrap(),
    )
    .unwrap();
    let declarative = mapper(DEFINITION).map(&source).unwrap();
    assert_eq!(
        irmind_app::common_event::encode_common_event(&native).unwrap(),
        irmind_app::common_event::encode_common_event(&declarative.record().common).unwrap()
    );
}

#[test]
fn interval_overlap_and_unknown_constants_are_rejected_before_activation() {
    let interval = DEFINITION
        .replace(
            "op = \"text\", value = \"failed\"",
            "op = \"integer_interval\", value = { first = 400, last = 499 }",
        )
        .replace(
            "op = \"text\", value = \"accepted\"",
            "op = \"integer_interval\", value = { first = 200, last = 299 }",
        );
    assert!(TableMapping::review(&interval).is_ok());
    assert!(
        TableMapping::review(
            &interval.replace("first = 200, last = 299", "first = 499, last = 599")
        )
        .is_err()
    );
    assert!(
        TableMapping::review(&DEFINITION.replace("authentication", "invented_category")).is_err()
    );
    assert!(
        TableMapping::review(
            &DEFINITION.replace("outcome = \"failure\"", "outcome = \"invented\"")
        )
        .is_err()
    );
}

#[test]
fn absence_null_and_present_are_distinct_and_missing_status_never_infers_failure() {
    let definition = DEFINITION
        .replace("op = \"text\", value = \"failed\"", "op = \"missing\"")
        .replace("op = \"text\", value = \"accepted\"", "op = \"null\"");
    let mapper = mapper(&definition);
    let missing = source(SourceValue::object(vec![]).unwrap());
    let null = source(SourceValue::object(vec![("status".into(), SourceValue::Null)]).unwrap());
    let present =
        source(SourceValue::object(vec![("status".into(), SourceValue::Boolean(false))]).unwrap());
    assert_eq!(
        mapper
            .map(&missing)
            .unwrap()
            .record()
            .common
            .event()
            .outcome(),
        EventOutcome::Failure
    );
    assert_eq!(
        mapper.map(&null).unwrap().record().common.event().outcome(),
        EventOutcome::Success
    );
    assert_eq!(
        mapper
            .map(&present)
            .unwrap()
            .record()
            .common
            .event()
            .outcome(),
        EventOutcome::Unknown
    );
}

#[test]
fn rule_fields_and_original_action_use_only_explicit_segmented_paths() {
    let rule = DEFINITION.replace(
        "parser_versions = [\"json-source-v1\"]",
        "parser_versions = [\"json-source-v1\"]\naction = [\"original_action\"]",
    );
    let rule = rule.replace(
        "[[fields]]\nsource = [\"client\"]",
        "[[rules.fields]]\nsource = [\"client\"]",
    );
    let source = source(
        SourceValue::object(vec![
            ("status".into(), SourceValue::Text("accepted".into())),
            (
                "original_action".into(),
                SourceValue::Text("ProviderOperation".into()),
            ),
            ("client".into(), SourceValue::Text("203.0.113.7".into())),
        ])
        .unwrap(),
    );
    let output = mapper(&rule).map(&source).unwrap();
    assert_eq!(
        output.record().common.event().action(),
        Some("ProviderOperation")
    );
    assert_eq!(output.record().common.observations().values().len(), 1);
}

#[test]
fn current_primary_conditions_bind_the_selector_and_definition_identity() {
    let narrowed = DEFINITION.replacen(
        "[[rules]]",
        "[[when]]\npath = [\"source_version\"]\npredicate = { op = \"present\" }\n\n[[rules]]",
        1,
    );
    let broad = mapper(DEFINITION);
    let narrow = mapper(&narrowed);
    assert_ne!(broad.manifest().identity(), narrow.manifest().identity());
    assert!(
        !narrow.manifest().selectors()[0].matches(&source(SourceValue::object(vec![]).unwrap()))
    );
}

#[test]
fn current_interpreter_binds_display_projection_and_rejects_retired_or_missing_interpreters() {
    let definition = DEFINITION.replacen(
        "[[rules]]",
        "action = [\"original_action\"]\n\n[[rules]]",
        1,
    );
    let record = source(
        SourceValue::object(vec![(
            "original_action".into(),
            SourceValue::Text("OriginalAction".into()),
        )])
        .unwrap(),
    );
    let current = mapper(&definition).map(&record).unwrap();
    assert_eq!(current.record().indexed.record.event, "OriginalAction");
    for retired in ["irmind-mapping-tables-v1", "unknown"] {
        assert!(
            TableMapping::review(&definition.replace("irmind-mapping-tables-v2", retired)).is_err()
        );
    }
    assert!(
        TableMapping::review(&definition.replacen(
            "interpreter = \"irmind-mapping-tables-v2\"\n",
            "",
            1
        ))
        .is_err()
    );
}
