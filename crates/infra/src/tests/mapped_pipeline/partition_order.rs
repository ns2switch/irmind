use super::*;
use irmind_domain::{PartitionOverflowReason, ScopePartitionKey, ScopePartitionValue};

#[test]
fn disordered_sources_allocate_host_partitions_by_the_shared_stable_order() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let input = root.path().join("events.jsonl");
    let rows = (0..65)
        .rev()
        .map(|index| {
            format!(
                r#"{{"eventTime":"2026-11-01T00:00:00.{index:09}Z","host":"endpoint-{index:02}"}}"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(input, rows).unwrap();
    let case = engine
        .create_case("Stable host allocation", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    cases
        .ingest_local_batch(
            &case.id,
            root.path(),
            &["events.jsonl".into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    let catalog = irmind_app::artifact_catalog(&store.entries(&case.id).unwrap()).unwrap();
    let mut values = std::collections::BTreeSet::new();
    for artifact in catalog.active {
        let ParquetArtifact::V3(artifact) = artifact else {
            panic!("current envelope required");
        };
        assert!(!artifact.core().path.contains("endpoint-"));
        let scope = artifact
            .core()
            .partition
            .scopes
            .iter()
            .find(|scope| scope.key == ScopePartitionKey::Host)
            .unwrap();
        assert_eq!(scope.cap, 64);
        values.insert(scope.value.clone());
    }
    for host in 0..64 {
        assert!(values.contains(&ScopePartitionValue::Ordinary(format!(
            "endpoint-{host:02}"
        ))));
    }
    assert!(values.contains(&ScopePartitionValue::Overflow(
        PartitionOverflowReason::Cardinality
    )));
    assert!(!values.contains(&ScopePartitionValue::Ordinary("endpoint-64".into())));
    assert_eq!(
        cases
            .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
            .unwrap(),
        1
    );
    assert_eq!(
        fs::read_dir(store.parquet.case_dir(&case.id).unwrap().join("spool"))
            .unwrap()
            .count(),
        0
    );
}
