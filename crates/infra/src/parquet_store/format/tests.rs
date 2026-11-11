#![allow(clippy::unwrap_used)]
use super::*;
use arrow::array::TimestampMicrosecondArray;
use irmind_app::CancellationToken;
use irmind_domain::CaseId;

#[test]
fn cached_source_binding_still_rejects_changed_hashes_and_null_indexes() {
    let source = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = crate::parquet_store::fixtures::store(data.path());
    let id = CaseId::parse("00000000-0000-0000-0000-000000000026").unwrap();
    std::fs::write(
        source.path().join("input.json"),
        br#"{"eventTime":"2026-11-01T00:00:00Z"}"#,
    )
    .unwrap();
    let prepared = crate::parquet_store::fixtures::one_source(
        &store,
        &id,
        source.path(),
        "input.json",
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let artifact = &prepared.artifacts[0];
    let hash = prepared.manifest.sha256.as_str();
    let foreign = "0".repeat(64);
    assert_ne!(hash, foreign);
    let names = [(hash.into(), "input.json".into())].into_iter().collect();
    let batch = |hashes: Vec<&str>, indexes: Vec<Option<u64>>| {
        RecordBatch::try_from_iter(vec![
            (
                "source_hash",
                Arc::new(StringArray::from(hashes)) as ArrayRef,
            ),
            (
                "record_index",
                Arc::new(UInt64Array::from(indexes)) as ArrayRef,
            ),
            (
                "event_time",
                Arc::new(TimestampMicrosecondArray::from(vec![0, 0]).with_timezone("UTC"))
                    as ArrayRef,
            ),
        ])
        .unwrap()
    };
    assert!(
        normalize_batch(
            &batch(vec![hash, &foreign], vec![Some(0), Some(1)]),
            artifact,
            &names,
            false
        )
        .is_err()
    );
    assert!(
        normalize_batch(
            &batch(vec![hash, hash], vec![Some(0), None]),
            artifact,
            &names,
            false
        )
        .is_err()
    );
    let valid = normalize_batch(
        &batch(vec![hash, hash], vec![Some(0), Some(1)]),
        artifact,
        &names,
        false,
    )
    .unwrap();
    assert_eq!(valid.num_rows(), 2);
    assert_eq!(
        super::super::query::text(&valid, "_irmind_source", 1).unwrap(),
        "input.json"
    );
}

#[test]
fn current_physical_families_do_not_alias_retired_schemas() {
    let current = [
        "irmind-events-v4",
        "irmind-entities-v4",
        "irmind-coobservations-v3",
    ];
    for a in current {
        for b in current {
            assert_eq!(same_family(a, b), a == b);
        }
        for retired in [
            "irmind-events-v2",
            "irmind-events-v3",
            "irmind-entities-v1",
            "irmind-entities-v2",
            "irmind-entities-v3",
            "irmind-coobservations-v1",
            "irmind-coobservations-v2",
        ] {
            assert!(!same_family(retired, a));
            assert!(!same_family(a, retired));
        }
    }
}
