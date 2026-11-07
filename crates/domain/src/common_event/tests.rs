#![allow(clippy::unwrap_used)]
use super::*;
use crate::EvidenceHash;

fn origin() -> EventOrigin {
    EventOrigin::try_new(
        EvidenceHash::parse(&"ab".repeat(32)).unwrap(),
        7,
        Some(42),
        "parser-test",
        "test-v1",
    )
    .unwrap()
}
fn ip(role: EntityRole, field: CommonField) -> EntityObservation {
    EntityObservation::try_new(
        ObservedEntity::try_new(
            ObservedEntityKind::Ip,
            "203.0.113.77",
            EntityIdentityScope::Global,
        )
        .unwrap(),
        role,
        field,
    )
    .unwrap()
}

#[test]
fn all_wire_codes_match_the_frozen_table() {
    let mut rows = Vec::new();
    macro_rules! rows {
        ($name:ident) => {
            for value in $name::ALL {
                rows.push(format!(
                    "{}\t{}\t{}",
                    stringify!($name),
                    value.code(),
                    value.as_str()
                ));
                assert_eq!($name::from_code(value.code()).unwrap(), *value);
                assert_eq!($name::parse(value.as_str()).unwrap(), *value);
            }
        };
    }
    rows!(EventCategory);
    rows!(EventType);
    rows!(EventOutcome);
    rows!(EventKind);
    rows!(EntityRole);
    for field in CommonField::all() {
        rows.push(format!("CommonField\t{}\t{}", field.code(), field.as_str()));
        assert_eq!(CommonField::from_code(field.code()).unwrap(), field);
        assert_eq!(CommonField::parse(field.as_str()).unwrap(), field);
    }
    assert_eq!(rows.join("\n") + "\n", include_str!("goldens/codes-v1.tsv"));
}

#[test]
fn category_and_type_bits_reject_unknown_codes() {
    assert!(CategorySet::from_bits(1 << 20).is_err());
    assert!(EventTypeSet::from_bits(1 << 18).is_err());
    assert!(EventOutcome::from_code(3).is_err());
    assert!(EntityRole::from_code(0).is_err());
    assert!(CommonField::from_code(0).is_err());
    assert!(CommonField::parse("arbitrary_json.path").is_err());
}

#[test]
fn unmapped_events_have_no_invented_classification() {
    let event = CommonEventV1::try_new(
        origin(),
        None,
        EventHeaderV1::default(),
        EventContextV1::default(),
        BoundedObservations::default(),
    )
    .unwrap();
    assert_eq!(event.event().categories().bits(), 0);
    assert_eq!(event.event().types().bits(), 0);
    assert_eq!(event.event().outcome(), EventOutcome::Unknown);
    assert!(event.timestamp().is_none());
}

#[test]
fn same_ip_has_distinct_occurrences_in_two_roles() {
    let mut context = EventContextV1::default();
    for field in [CommonField::SourceIp, CommonField::DestinationIp] {
        context
            .try_insert(field, CommonValue::Ip("203.0.113.77".parse().unwrap()))
            .unwrap();
    }
    let source = ip(EntityRole::Source, CommonField::SourceIp);
    let destination = ip(EntityRole::Destination, CommonField::DestinationIp);
    let observations =
        BoundedObservations::try_new(vec![source.clone(), source, destination]).unwrap();
    let event = CommonEventV1::try_new(
        origin(),
        None,
        EventHeaderV1::default(),
        context,
        observations,
    )
    .unwrap();
    assert_eq!(event.observations().values().len(), 2);
}

#[test]
fn actor_and_target_cannot_be_swapped() {
    let actor = ObservedEntity::try_new(
        ObservedEntityKind::User,
        "alice",
        EntityIdentityScope::Account(EventText::identifier("tenant").unwrap()),
    )
    .unwrap();
    assert!(
        EntityObservation::try_new(actor.clone(), EntityRole::Target, CommonField::UserName)
            .is_err()
    );
    assert!(
        EntityObservation::try_new(actor, EntityRole::Actor, CommonField::UserTargetName).is_err()
    );
}

#[test]
fn reused_pid_does_not_form_a_global_identity() {
    let scoped = |record| {
        ObservedEntity::try_new(
            ObservedEntityKind::Process,
            "42",
            EntityIdentityScope::SourceRecord {
                source: origin().source().clone(),
                record,
            },
        )
        .unwrap()
    };
    assert_ne!(scoped(7), scoped(8));
    assert!(
        ObservedEntity::try_new(
            ObservedEntityKind::Process,
            "42",
            EntityIdentityScope::Global
        )
        .is_err()
    );
    assert!(
        ObservedEntity::try_new(
            ObservedEntityKind::Process,
            "42",
            EntityIdentityScope::Host(EventText::identifier("host").unwrap())
        )
        .is_err()
    );
}

#[test]
fn checked_fields_reject_wrong_types_ranges_and_duplicate_assignments() {
    let mut context = EventContextV1::default();
    assert!(
        context
            .try_insert(CommonField::SourcePort, CommonValue::Unsigned(65_536))
            .is_err()
    );
    assert!(
        context
            .try_insert(CommonField::ProcessPid, CommonValue::Unsigned(u64::MAX))
            .is_err()
    );
    assert!(
        context
            .try_insert(
                CommonField::SourceIp,
                CommonValue::Text(EventText::new("not an IP").unwrap())
            )
            .is_err()
    );
    context
        .try_insert(CommonField::SourcePort, CommonValue::Unsigned(0))
        .unwrap();
    assert!(
        context
            .try_insert(CommonField::SourcePort, CommonValue::Unsigned(1))
            .is_err()
    );
    assert!(ContentHash::new(HashAlgorithm::Sha256, "abcd").is_err());
}

#[test]
fn observation_value_must_match_its_typed_context() {
    let mut context = EventContextV1::default();
    context
        .try_insert(
            CommonField::SourceIp,
            CommonValue::Ip("203.0.113.1".parse().unwrap()),
        )
        .unwrap();
    let observations =
        BoundedObservations::try_new(vec![ip(EntityRole::Source, CommonField::SourceIp)]).unwrap();
    assert!(
        CommonEventV1::try_new(
            origin(),
            None,
            EventHeaderV1::default(),
            context,
            observations
        )
        .is_err()
    );
}

#[test]
fn source_scoped_observation_cannot_point_to_another_record() {
    let entity = ObservedEntity::try_new(
        ObservedEntityKind::Process,
        "42",
        EntityIdentityScope::SourceRecord {
            source: origin().source().clone(),
            record: 8,
        },
    )
    .unwrap();
    let observation =
        EntityObservation::try_new(entity, EntityRole::Subject, CommonField::ProcessPid).unwrap();
    let mut context = EventContextV1::default();
    context
        .try_insert(CommonField::ProcessPid, CommonValue::Unsigned(42))
        .unwrap();
    assert!(
        CommonEventV1::try_new(
            origin(),
            None,
            EventHeaderV1::default(),
            context,
            BoundedObservations::try_new(vec![observation]).unwrap()
        )
        .is_err()
    );
}

#[test]
fn payloads_and_observations_are_bounded_and_debug_is_redacted() {
    assert!(EventText::new(&"x".repeat(8193)).is_err());
    assert!(EventText::identifier("host\nspoof").is_err());
    assert!(
        BoundedObservations::try_new(vec![ip(EntityRole::Source, CommonField::SourceIp); 33])
            .is_err()
    );
    let secret = EventText::new("sensitive-command").unwrap();
    assert!(!format!("{secret:?}").contains("sensitive-command"));
    let mut context = EventContextV1::default();
    for field in [
        CommonField::ProcessCommandLine,
        CommonField::ProcessParentCommandLine,
    ] {
        context
            .try_insert(
                field,
                CommonValue::Text(EventText::new(&"\\".repeat(8192)).unwrap()),
            )
            .unwrap();
    }
    assert!(
        context
            .try_insert(
                CommonField::UrlOriginal,
                CommonValue::Text(EventText::new(&"\\".repeat(8192)).unwrap())
            )
            .is_err()
    );
}

#[test]
fn graph_predicates_are_closed_and_invalid_input_never_becomes_an_empty_filter() {
    use crate::GraphQueryFilter;
    use std::collections::BTreeMap;
    let mut arguments = BTreeMap::from([
        ("event_category".into(), "authentication".into()),
        ("event_type".into(), "start".into()),
        ("event_outcome".into(), "failure".into()),
        ("entity_role".into(), "actor".into()),
    ]);
    let filter = GraphQueryFilter::from_args(&arguments).unwrap();
    assert!(!filter.is_empty());
    assert_eq!(filter.common().outcome, Some(EventOutcome::Failure));
    for key in [
        "event_category",
        "event_type",
        "event_outcome",
        "entity_role",
    ] {
        let old = arguments
            .insert(key.into(), "unknown-or-injected".into())
            .unwrap();
        assert!(GraphQueryFilter::from_args(&arguments).is_err());
        arguments.insert(key.into(), old);
    }
}
