use super::batch::{Delayed, id};
use super::*;
use crate::parquet_store::ParquetStore;
use irmind_app::{CancellationToken, LargeCaseStore, LocalBatchRequest};
use irmind_domain::GraphQueryFilter;

#[test]
fn exact_host_filters_include_overflow_and_legacy_without_merging_collisions() {
    let inputs = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = ParquetStore::open_precise(data.path()).unwrap();
    let legacy = ParquetStore::open(data.path()).unwrap();
    let rows = [
        ("a.json", "HOST-A", "203.0.113.8"),
        ("b.json", "host-a", "203.0.113.9"),
        ("c.json", "host-b", "203.0.113.10"),
        ("old.json", "host-old", "203.0.113.11"),
    ];
    write_inputs(inputs.path(), &rows);
    let paths = ["a.json".into(), "b.json".into(), "c.json".into()];
    let mut prepared = store
        .prepare_local_batch(
            LocalBatchRequest {
                case_id: &id(),
                source_root: inputs.path(),
                relative_paths: &paths,
                copy_original: false,
                parser: &Delayed {
                    reverse: false,
                    fail: false,
                },
                committed_artifacts: &[],
                limits: PartitionLimits {
                    host: 1,
                    ..PartitionLimits::default()
                },
            },
            &CancellationToken::new(),
        )
        .unwrap();
    prepared.push(
        legacy
            .prepare_local(
                &id(),
                inputs.path(),
                "old.json",
                false,
                &irmind_mod_parser_json::JsonParser,
                &CancellationToken::new(),
            )
            .unwrap(),
    );
    let artifacts = prepared
        .iter()
        .flat_map(|p| p.artifacts.clone())
        .collect::<Vec<_>>();
    let names = source_names(&prepared);
    let queries = store.queries(&names);
    let summary = queries
        .summary_native(&id(), &artifacts, &CancellationToken::new())
        .unwrap();
    assert!(
        summary.contains("overflow files=1 (cardinality=1"),
        "{summary}"
    );
    for (index, (_, host, ip)) in rows.into_iter().enumerate() {
        let filter =
            GraphQueryFilter::parse_with_host(None, None, None, None, None, Some(host)).unwrap();
        let timeline = queries
            .timeline_native(&id(), &artifacts, &filter, 20, &CancellationToken::new())
            .unwrap();
        assert_eq!(timeline.len(), 1, "{host}");
        assert_eq!(
            timeline[0].evidence_hash,
            prepared[index].manifest.sha256.as_str()
        );
        let entity = queries
            .entity_native(
                &id(),
                &artifacts,
                &filter,
                "ip",
                ip,
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(entity.contains("count=1;"), "{entity}");
    }
}

fn write_inputs(inputs: &std::path::Path, rows: &[(&str, &str, &str)]) {
    for (name, host, ip) in rows.iter().copied() {
        let raw = serde_json::json!({"eventTime":"2026-11-01T00:00:00Z","eventName":"Login","host":host,"sourceIPAddress":ip});
        std::fs::write(inputs.join(name), serde_json::to_vec(&raw).unwrap()).unwrap();
    }
}

fn source_names(
    sources: &[irmind_app::PreparedSource],
) -> std::collections::BTreeMap<String, String> {
    sources
        .iter()
        .map(|p| (p.manifest.sha256.as_str().into(), p.manifest.source.clone()))
        .collect()
}
