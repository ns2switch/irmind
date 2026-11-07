#![allow(clippy::unwrap_used)]
use crate::parquet_store::RecordRow;
use irmind_app::common_event::*;
use irmind_app::{GraphRecord, IndexedGraphRecord, ParserIdentity};
use irmind_domain::{EvidenceHash, Provenance, SourceKind};

fn row() -> RecordRow {
    let hash = EvidenceHash::parse(&"ab".repeat(32)).unwrap();
    let identity = ParserIdentity {
        name: "parser-test",
        version: "test-v1",
    };
    let mut context = EventContextV1::default();
    let mut observations = Vec::new();
    for (field, role) in [
        (CommonField::SourceIp, EntityRole::Source),
        (CommonField::DestinationIp, EntityRole::Destination),
    ] {
        context
            .try_insert(field, CommonValue::Ip("203.0.113.77".parse().unwrap()))
            .unwrap();
        observations.push(
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
            .unwrap(),
        );
    }
    let record = CommonGraphRecord {
        common: CommonEventV1::try_new(
            EventOrigin::try_new(hash.clone(), 7, Some(42), identity.name, identity.version)
                .unwrap(),
            None,
            EventHeaderV1::default(),
            context,
            BoundedObservations::try_new(observations).unwrap(),
        )
        .unwrap(),
        indexed: IndexedGraphRecord {
            record: GraphRecord {
                index: 7,
                at: String::new(),
                event: "Observe".into(),
                text: "{}".into(),
                entities: vec![
                    ("user".into(), "alice".into()),
                    ("ip".into(), "203.0.113.77".into()),
                    ("user".into(), "alice".into()),
                ],
                relations: Vec::new(),
            },
            time: None,
            source_offset: Some(42),
        },
    };
    let checked = check_common_record(
        &record,
        &Provenance::new([0xab; 32], Some(7), SourceKind::File),
        identity,
    )
    .unwrap();
    RecordRow::from_common(&checked, &hash).unwrap()
}

#[test]
fn spool_cache_elision_keeps_memory_accounting_and_all_physical_bytes() {
    let original = row();
    let encoded = serde_json::to_string(&original).unwrap();
    let mut repeated: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    let common = original.common.as_ref().unwrap();
    repeated["common"]["co_observations"] = serde_json::json!(common.co_observations);
    assert!(encoded.len() < serde_json::to_string(&repeated).unwrap().len());
    let restored: RecordRow = serde_json::from_str(&encoded).unwrap();
    assert_eq!(original.estimated_bytes(), restored.estimated_bytes());
    assert_eq!(original.entity_pairs, restored.entity_pairs);
    assert_eq!(
        original.entity_pairs,
        vec![
            ("ip".into(), "203.0.113.77".into()),
            ("user".into(), "alice".into())
        ]
    );
    assert_eq!(
        common.co_observations,
        restored.common.as_ref().unwrap().co_observations
    );
    for family in 0..3 {
        let batch = |rows: &[RecordRow]| match family {
            0 => super::super::batches::events(rows),
            1 => super::super::batches::entities(rows, false),
            _ => super::super::batches::entities(rows, true),
        };
        let first = batch(std::slice::from_ref(&original)).unwrap();
        let second = batch(std::slice::from_ref(&restored)).unwrap();
        assert_eq!(first, second);
        assert_eq!(parquet_bytes(&first), parquet_bytes(&second));
    }
}

fn parquet_bytes(batch: &arrow::record_batch::RecordBatch) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer =
        parquet::arrow::ArrowWriter::try_new(&mut bytes, batch.schema(), None).unwrap();
    writer.write(batch).unwrap();
    writer.close().unwrap();
    bytes
}
