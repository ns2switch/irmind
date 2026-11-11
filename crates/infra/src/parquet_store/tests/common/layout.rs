//! Physical reader/compactor tests; signed catalog activation has separate contracts.
use super::*;
use irmind_domain::{ArtifactPipelineV1, ParquetArtifactV3, ParquetLayoutV1};

#[test]
#[allow(clippy::too_many_lines)]
fn v3_readers_and_layout_keep_exact_query_results_and_parent_files() {
    let root = tempfile::tempdir().unwrap();
    let store = mapped::store(root.path());
    let id = CaseId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    for (name, second) in [("a.json", "01"), ("b.json", "02")] {
        fs::write(root.path().join(name), format!(
            "{{\"eventTime\":\"2026-11-01T00:00:{second}.123456789Z\",\"eventName\":\"Login\",\"source_ip\":\"203.0.113.1\",\"destination_ip\":\"203.0.113.1\",\"outcome\":\"failure\"}}"
        )).unwrap();
    }
    let paths = ["a.json".into(), "b.json".into()];
    let token = CancellationToken::new();
    let prepared = crate::parquet_store::fixtures::successive_sources(
        &store,
        irmind_app::MappedIngestRequest {
            case_id: &id,
            source_root: root.path(),
            relative_paths: &paths,
            copy_original: false,
            parser: &crate::parquet_store::fixtures::parser(),
            committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(&[]),
            limits: irmind_app::PartitionLimits::default(),
        },
        &token,
    )
    .unwrap();
    let names = prepared
        .iter()
        .zip(paths)
        .map(|(p, n)| (p.manifest.sha256.as_str().into(), n))
        .collect::<BTreeMap<_, _>>();
    let historical = prepared
        .iter()
        .flat_map(|p| p.artifacts.clone())
        .collect::<Vec<_>>();
    let mapped = historical.clone();
    let mut compacted = Vec::new();
    for schema in [
        "irmind-events-v4",
        "irmind-entities-v4",
        "irmind-coobservations-v3",
    ] {
        let inputs = mapped
            .iter()
            .filter(|a| a.schema_version() == schema)
            .cloned()
            .collect::<Vec<_>>();
        let child = store.compact_artifacts(&id, &inputs, &token).unwrap();
        let parents = inputs
            .iter()
            .map(|a| match a {
                ParquetArtifact::V3(v) => v.clone(),
            })
            .collect::<Vec<_>>();
        let ParquetArtifact::V3(value) = &child;
        ParquetLayoutV1::between(&parents, value)
            .unwrap()
            .verify(&parents, value)
            .unwrap();
        for parent in &parents {
            assert!(
                store
                    .case_dir(&id)
                    .unwrap()
                    .join(&parent.core().path)
                    .is_file()
            );
        }
        compacted.push(child);
    }
    let query = store.queries(&names);
    let filter = GraphQueryFilter::default();
    for selected in [&mapped, &compacted] {
        assert_eq!(
            query
                .entity_native(&id, &historical, &filter, "ip", "203.0.113.1", &token)
                .unwrap(),
            query
                .entity_native(&id, selected, &filter, "ip", "203.0.113.1", &token)
                .unwrap()
        );
        assert_eq!(
            query
                .timeline_native(&id, &historical, &filter, 20, &token)
                .unwrap()
                .into_iter()
                .map(|e| (e.at, e.event, e.evidence_hash, e.record_index))
                .collect::<Vec<_>>(),
            query
                .timeline_native(&id, selected, &filter, 20, &token)
                .unwrap()
                .into_iter()
                .map(|e| (e.at, e.event, e.evidence_hash, e.record_index))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            query
                .search_native(&id, &historical, &filter, "Login", 20, &token)
                .unwrap(),
            query
                .search_native(&id, selected, &filter, "Login", 20, &token)
                .unwrap()
        );
    }
    let ParquetArtifact::V3(value) = compacted
        .iter()
        .find(|a| a.schema_version() == "irmind-events-v4")
        .unwrap();
    let changed = ParquetArtifactV3::try_new(
        value.core().clone(),
        ArtifactPipelineV1::layout(
            value.bindings().to_vec(),
            1,
            match value.pipeline().derivation() {
                irmind_domain::ArtifactDerivationV1::Layout { parents } => parents.clone(),
                irmind_domain::ArtifactDerivationV1::Mapped => unreachable!(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        query
            .timeline_native(&id, &[changed.into()], &filter, 20, &token)
            .is_err()
    );
}
