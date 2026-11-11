use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn scoped_roles_and_pid_lifetimes_survive_compaction_and_reconstruction() {
    let root = tempfile::tempdir().unwrap();
    let store = mapped::store(root.path());
    let id = CaseId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    fs::write(root.path().join("a.json"),br#"{"eventTime":"2026-11-01T00:00:00.000001Z","eventName":"Login","source_ip":"203.0.113.1","destination_ip":"203.0.113.1","pid":42}"#).unwrap();
    fs::write(root.path().join("b.json"),br#"{"eventTime":"2026-11-01T00:00:00.000002Z","eventName":"Login","source_ip":"203.0.113.2","pid":42}"#).unwrap();
    let paths = ["a.json".into(), "b.json".into()];
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
        &CancellationToken::new(),
    )
    .unwrap();
    let names = prepared
        .iter()
        .zip(paths)
        .map(|(p, name)| (p.manifest.sha256.as_str().into(), name))
        .collect::<BTreeMap<_, _>>();
    let all = prepared
        .iter()
        .flat_map(|p| p.artifacts.clone())
        .collect::<Vec<_>>();
    let mut bundles = Vec::new();
    let token = CancellationToken::new();
    for schema in [
        "irmind-events-v4",
        "irmind-entities-v4",
        "irmind-coobservations-v3",
    ] {
        let inputs = all
            .iter()
            .filter(|a| a.schema_version() == schema)
            .cloned()
            .collect::<Vec<_>>();
        bundles.push(store.compact_artifacts(&id, &inputs, &token).unwrap());
    }
    for artifact in &bundles {
        let builder = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            File::open(store.case_dir(&id).unwrap().join(artifact.path())).unwrap(),
        )
        .unwrap();
        crate::parquet_store::format::validate_schema(artifact, builder.schema()).unwrap();
    }
    let query = store.queries(&names);
    let filter = GraphQueryFilter::default();
    for (kind, value) in [("ip", "203.0.113.1"), ("process", "42")] {
        assert_eq!(
            query
                .entity_native(&id, &all, &filter, kind, value, &token)
                .unwrap(),
            query
                .entity_native(&id, &bundles, &filter, kind, value, &token)
                .unwrap()
        );
    }
    let path = query
        .path_native(
            &id,
            &bundles,
            &filter,
            ("ip", "203.0.113.1"),
            ("ip", "203.0.113.2"),
            &token,
        )
        .unwrap();
    assert!(path.contains("no co-observation path"), "{path}");
    assert!(
        prepared
            .iter()
            .all(|p| p.mapping.records() == p.records as u64)
    );
    mapped::assert_rebuild(root.path(), &["a.json".into(), "b.json".into()], true);
}
