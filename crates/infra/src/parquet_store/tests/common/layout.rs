//! Physical reader/compactor tests; signed catalog activation has separate contracts.
use super::*;
use irmind_domain::{
    ArtifactPipelineV1, EvidenceHash, MappingBindingV1, MappingInputRefV1, ParquetArtifactV3,
    ParquetLayoutV1, SourceDecoderIdentityV1,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder as Reader;

fn wrap(store: &ParquetStore, id: &CaseId, artifact: &ParquetArtifact) -> ParquetArtifact {
    let core = artifact.precise_metadata().unwrap().clone();
    let file = File::open(store.case_dir(id).unwrap().join(&core.path)).unwrap();
    let reader = Reader::try_new(file).unwrap();
    let rows = u64::try_from(reader.metadata().file_metadata().num_rows()).unwrap();
    let source = core.source_hashes[0].clone();
    let input = MappingInputRefV1::try_new(source.clone(), source.clone(), 2).unwrap();
    let binding = MappingBindingV1::new(
        input,
        source.clone(),
        EvidenceHash::from_bytes([42; 32]),
        SourceDecoderIdentityV1::try_new(&core.parser_id, &core.parser_version).unwrap(),
        None,
    );
    ParquetArtifactV3::try_new(
        core,
        ArtifactPipelineV1::mapped(vec![binding], rows).unwrap(),
    )
    .unwrap()
    .into()
}

#[test]
#[allow(clippy::too_many_lines)]
fn v3_readers_and_layout_keep_exact_query_results_and_parent_files() {
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open_common(root.path()).unwrap();
    let id = CaseId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    for (name, second) in [("a.json", "01"), ("b.json", "02")] {
        fs::write(root.path().join(name), format!(
            "{{\"eventTime\":\"2026-11-01T00:00:{second}.123456789Z\",\"eventName\":\"Login\",\"source_ip\":\"203.0.113.1\",\"destination_ip\":\"203.0.113.1\",\"outcome\":\"failure\"}}"
        )).unwrap();
    }
    let paths = ["a.json".into(), "b.json".into()];
    let token = CancellationToken::new();
    let prepared = store
        .prepare_local_batch(
            irmind_app::LocalBatchRequest {
                case_id: &id,
                source_root: root.path(),
                relative_paths: &paths,
                copy_original: false,
                parser: &mapped::Mapped,
                committed_artifacts: &[],
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
    let mapped = historical
        .iter()
        .map(|a| wrap(&store, &id, a))
        .collect::<Vec<_>>();
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
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        let ParquetArtifact::V3(value) = &child else {
            unreachable!()
        };
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
    let ParquetArtifact::V3(value) = mapped
        .iter()
        .find(|a| a.schema_version() == "irmind-events-v4")
        .unwrap()
    else {
        unreachable!()
    };
    let changed = ParquetArtifactV3::try_new(
        value.core().clone(),
        ArtifactPipelineV1::mapped(value.bindings().to_vec(), 2).unwrap(),
    )
    .unwrap();
    assert!(
        query
            .timeline_native(&id, &[changed.into()], &filter, 20, &token)
            .is_err()
    );
}
