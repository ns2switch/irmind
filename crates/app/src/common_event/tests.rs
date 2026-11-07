#![allow(clippy::unwrap_used)]
use super::*;
use irmind_domain::*;

fn projection() -> CommonEventV1 {
    let origin = EventOrigin::try_new(
        EvidenceHash::parse(&"ab".repeat(32)).unwrap(),
        7,
        Some(42),
        "parser-test",
        "test-v1",
    )
    .unwrap();
    let header = EventHeaderV1::new(
        CategorySet::new([EventCategory::Network]),
        EventTypeSet::new([EventType::Connection]),
        EventOutcome::Unknown,
        EventKind::Event,
    )
    .with_action("connect")
    .unwrap();
    let mut context = EventContextV1::default();
    context
        .try_insert(
            CommonField::SourceIp,
            CommonValue::Ip("203.0.113.77".parse().unwrap()),
        )
        .unwrap();
    let entity = ObservedEntity::try_new(
        ObservedEntityKind::Ip,
        "203.0.113.77",
        EntityIdentityScope::Global,
    )
    .unwrap();
    let observation =
        EntityObservation::try_new(entity, EntityRole::Source, CommonField::SourceIp).unwrap();
    CommonEventV1::try_new(
        origin,
        Some(
            IndexedTime::new(
                IndexedInstant::new(1_000_000, 789).unwrap(),
                TimePrecision::Nanosecond,
                false,
            )
            .unwrap(),
        ),
        header,
        context,
        BoundedObservations::try_new(vec![observation]).unwrap(),
    )
    .unwrap()
}
#[test]
fn canonical_projection_matches_new_golden_and_round_trips() {
    let event = projection();
    let json = encode_common_event(&event).unwrap();
    assert_eq!(json, include_str!("goldens/network-v1.json").trim_end());
    assert_eq!(decode_common_event(&json).unwrap(), event);
}
#[test]
fn projection_rejects_unknown_fields_codes_duplicates_and_noncanonical_bytes() {
    let json = encode_common_event(&projection()).unwrap();
    assert!(decode_common_event(&json.replace("\"role\":3", "\"role\":0")).is_err());
    assert!(decode_common_event(&format!(" {json}")).is_err());
    assert!(decode_common_event(&json.replacen('{', "{\"unknown\":0,", 1)).is_err());
    assert!(
        decode_common_event(&json.replacen(
            "\"schema\":",
            "\"schema\":\"duplicate\",\"schema\":",
            1
        ))
        .is_err()
    );
    assert!(decode_common_event(&json.replace("\"source.ip\"", "\"arbitrary.path\"")).is_err());
}
#[test]
fn compatibility_bridge_never_classifies_evidence_text() {
    let indexed = IndexedGraphRecord {
        record: crate::GraphRecord {
            index: 7,
            at: String::new(),
            event: "failed attack".into(),
            text: r#"{"event":{"category":["authentication"],"outcome":"failure"},"user":"actor"}"#
                .into(),
            entities: vec![("user".into(), "actor".into())],
            relations: Vec::new(),
        },
        time: None,
        source_offset: None,
    };
    let tainted = Tainted::from_external(
        indexed.clone(),
        Provenance::new([0xab; 32], Some(7), SourceKind::File),
    );
    let identity = crate::ParserIdentity {
        name: "parser-test",
        version: "test-v1",
    };
    let common = lift_unclassified_common(&tainted, identity).unwrap();
    assert_eq!(common.provenance(), tainted.provenance());
    common.inspect(|record| {
        assert_eq!(record.indexed, indexed);
        assert_eq!(record.common.event().categories().bits(), 0);
        assert_eq!(record.common.event().outcome(), EventOutcome::Unknown);
        assert!(record.common.observations().values().is_empty());
        validate_common_record(record, common.provenance(), identity).unwrap();
    });
}
#[test]
fn boundary_rejects_changed_source_identity_or_time() {
    let common = projection();
    let indexed = IndexedGraphRecord {
        record: crate::GraphRecord {
            index: 7,
            at: String::new(),
            event: String::new(),
            text: "{}".into(),
            entities: Vec::new(),
            relations: Vec::new(),
        },
        time: common.timestamp(),
        source_offset: Some(42),
    };
    let record = CommonGraphRecord { indexed, common };
    let identity = crate::ParserIdentity {
        name: "parser-test",
        version: "test-v1",
    };
    assert!(
        validate_common_record(
            &record,
            &Provenance::new([0; 32], Some(7), SourceKind::File),
            identity
        )
        .is_err()
    );
    let provenance = Provenance::new([0xab; 32], Some(7), SourceKind::File);
    validate_common_record(&record, &provenance, identity).unwrap();
    let mut changed = record;
    changed.indexed.time = None;
    assert!(validate_common_record(&changed, &provenance, identity).is_err());
}

#[test]
fn context_time_keeps_unknown_precision_and_residual_nanoseconds() {
    let base = projection();
    let mut context = base.context().clone();
    let time = IndexedTime::new(
        IndexedInstant::new(1_000_000, 123).unwrap(),
        TimePrecision::Unknown,
        true,
    )
    .unwrap();
    context
        .try_insert(CommonField::FileCreated, CommonValue::Time(time))
        .unwrap();
    let event = CommonEventV1::try_new(
        base.origin().clone(),
        base.timestamp(),
        base.event().clone(),
        context,
        base.observations().clone(),
    )
    .unwrap();
    assert_eq!(
        decode_common_event(&encode_common_event(&event).unwrap()).unwrap(),
        event
    );
}
